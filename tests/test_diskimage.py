"""MBR detection and the SD-card burn, with the block device replaced by a file."""

from types import SimpleNamespace

from bigsigner import sdcard
from bigsigner.diskimage import RAM_MARGIN, CardBurner, looks_like_disk_image


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
    burner._mem_available = lambda: len(payload) + RAM_MARGIN
    result = burner.burn(source, on_card=True, progress=lambda *args: None)
    assert result.ok
    assert (ram / "image").read_bytes() == payload
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
