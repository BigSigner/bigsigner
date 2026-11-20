"""MBR detection and the SD-card burn, with the block device replaced by a file."""

import gzip
from types import SimpleNamespace

from bigsigner import sdcard
from bigsigner.diskimage import RAM_MARGIN, CardBurner, header_from_bytes, header_from_path, looks_like_disk_image


def _mbr(*entries):
    data = bytearray(512)
    for index, (status, partition_type, sectors) in enumerate(entries):
        offset = 446 + index * 16
        data[offset] = status
        data[offset + 4] = partition_type
        data[offset + 12:offset + 16] = int(sectors).to_bytes(4, "little")
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def test_a_bootable_fat_partition_is_a_disk_image():
    assert looks_like_disk_image(_mbr((0x80, 0x0C, 2048)))
    assert looks_like_disk_image(_mbr((0x80, 0x0C, 2048), (0x00, 0x83, 4096)))


def test_a_file_without_a_usable_partition_is_not_a_disk_image():
    assert not looks_like_disk_image(b"")
    assert not looks_like_disk_image(b"\x1f\x8b" + b"\0" * 510)
    blank = bytearray(512)
    blank[510:512] = b"\x55\xaa"
    assert not looks_like_disk_image(bytes(blank))
    assert not looks_like_disk_image(_mbr((0x00, 0xEE, 2048)))
    assert not looks_like_disk_image(_mbr((0x01, 0x0C, 2048)))


def test_a_gzip_member_is_recognized_from_its_first_uncompressed_sector(tmp_path):
    image = _mbr((0x80, 0x0C, 2048)) + b"\x00" * 1024
    packed = gzip.compress(image)
    assert looks_like_disk_image(header_from_bytes(packed))
    assert not looks_like_disk_image(header_from_bytes(gzip.compress(b"\xff" * 64)))
    path = tmp_path / "os.img.gz"
    path.write_bytes(packed)
    assert header_from_path(path) == image[:512]
    assert looks_like_disk_image(header_from_path(path))


def test_read_prefix_stops_after_the_requested_bytes():
    sdcard.mount_memory({"files": {"big.bin": b"abc" + b"\xff" * 1000}})
    try:
        assert sdcard.read_prefix("big.bin", size=3) == b"abc"
    finally:
        sdcard.unmount_memory()


def _burner(tmp_path, image=b"image-bytes", device_size=64):
    source = tmp_path / "os.img"
    source.write_bytes(image)
    device = tmp_path / "card"
    device.write_bytes(b"\xff" * device_size)
    burner = CardBurner(
        hold_path=tmp_path / "hold", device=device,
        microsd=str(tmp_path / "sd"), data=str(tmp_path / "data"),
    )
    burner._mounts = lambda: []
    burner._mount_boot = lambda: None
    return burner, source, device


def test_burn_writes_the_image_and_reads_it_back(tmp_path):
    payload = b"image-bytes"
    burner, source, device = _burner(tmp_path, payload)
    notes = []
    result = burner.burn(source, on_card=False, progress=lambda message, done, total: notes.append(message))
    assert result.ok and result.held and result.remove_card
    assert result.message == "The image was written."
    assert device.read_bytes()[:len(payload)] == payload
    assert (tmp_path / "hold").read_text() == "hold\n"
    assert "Writing the image\u2026" in notes
    assert "Verifying the image\u2026" in notes
    burner.release()
    assert not (tmp_path / "hold").exists()


def test_a_gzip_image_is_written_from_the_stream(tmp_path):
    payload = b"image-bytes" + b"\x00" * 40
    packed = gzip.compress(payload)
    burner, source, device = _burner(tmp_path, packed, device_size=len(payload) + 8)
    result = burner.burn(source, on_card=False, progress=lambda *args: None)
    assert result.ok, result.message
    assert device.read_bytes()[:len(payload)] == payload
    assert packed not in device.read_bytes()


def test_a_gzip_image_on_the_card_is_copied_while_still_compressed(tmp_path, monkeypatch):
    ram = tmp_path / "ram"
    ram.mkdir()
    monkeypatch.setattr(sdcard, "ram_directory", lambda name: ram)
    payload = b"from-the-card"
    packed = gzip.compress(payload)
    burner, source, device = _burner(tmp_path, packed, device_size=64)
    burner._mem_available = lambda: len(packed) + RAM_MARGIN
    result = burner.burn(source, on_card=True, progress=lambda *args: None)
    assert result.ok, result.message
    assert (ram / "image").read_bytes() == packed
    assert device.read_bytes()[:len(payload)] == payload


def test_a_busy_card_is_left_unwritten(tmp_path):
    burner, source, device = _burner(tmp_path)
    original = device.read_bytes()
    burner._mounts = lambda: [burner.microsd]

    def run(argv):
        return SimpleNamespace(returncode=1)

    burner._run = run
    result = burner.burn(source, on_card=False, progress=lambda *args: None)
    assert result.message == "The SD card is still in use."
    assert not result.ok and not result.held and not result.remove_card
    assert device.read_bytes() == original
    assert not (tmp_path / "hold").exists()


def test_an_image_larger_than_the_card_is_not_written(tmp_path):
    burner, source, device = _burner(tmp_path, b"x" * 100, device_size=16)
    original = device.read_bytes()
    result = burner.burn(source, on_card=False, progress=lambda *args: None)
    assert result.message == "This image is larger than the SD card."
    assert result.held and result.remove_card
    assert device.read_bytes() == original


def test_a_card_file_is_copied_into_ram_before_the_hold(tmp_path, monkeypatch):
    ram = tmp_path / "ram"
    ram.mkdir()
    monkeypatch.setattr(sdcard, "ram_directory", lambda name: ram)
    payload = b"from-the-card"
    burner, source, device = _burner(tmp_path, payload)
    burner._mem_available = lambda: 64 * 1024 + RAM_MARGIN
    result = burner.burn(source, on_card=True, progress=lambda *args: None)
    assert result.ok
    stored = (ram / "image").read_bytes()
    assert stored.startswith(b"\x1f\x8b")
    assert gzip.decompress(stored) == payload
    assert result.copy_path == str(ram / "image")
    assert device.read_bytes()[:len(payload)] == payload


def test_copy_stops_when_free_ram_cannot_hold_the_image(tmp_path):
    burner, source, device = _burner(tmp_path, b"x" * 1000)
    original = device.read_bytes()
    burner._mem_available = lambda: 100
    result = burner.burn(source, on_card=True, progress=lambda *args: None)
    assert result.message == "There is not enough free RAM to copy this image."
    assert not result.held and not result.remove_card
    assert device.read_bytes() == original
    assert not (tmp_path / "hold").exists()
