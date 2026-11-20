"""Recognize a raw MBR disk image and write it to the microSD card.

The running system is in RAM. The card is the boot device: partition 1 is the
FAT volume at ``/mnt/microsd``, and a dev image also mounts partition 2 at
``/mnt/data``. Writing the image replaces both. A hold file keeps mdev and
data-automount from mounting the card again while it is detached.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess

from . import sdcard

HOLD_PATH = Path("/tmp/bigsigner-sd-hold")
DEVICE = Path("/dev/mmcblk0")
MICROSD_MOUNT = "/mnt/microsd"
DATA_MOUNT = "/mnt/data"
# Leave the panel enough RAM to keep drawing while the copy is in flight.
RAM_MARGIN = 8 * 1024 * 1024
_CHUNK = 1024 * 1024


class BurnError(Exception):
    pass


def looks_like_disk_image(header: bytes) -> bool:
    """True for a DOS MBR disk image, such as a BigSigner OS ``.img``.

    The signature is the last two bytes of the first sector. A usable image
    also has a partition entry with status ``0x00`` or ``0x80``, a type other
    than empty or a GPT protective partition, and a non-zero sector count.
    """
    if len(header) < 512 or header[510:512] != b"\x55\xaa":
        return False
    types = []
    for index in range(4):
        entry = header[446 + index * 16:446 + (index + 1) * 16]
        status, partition_type = entry[0], entry[4]
        sectors = int.from_bytes(entry[12:16], "little")
        if status in (0x00, 0x80) and partition_type not in (0x00, 0xEE) and sectors:
            types.append(partition_type)
    return bool(types)


@dataclass
class BurnResult:
    ok: bool
    message: str
    copy_path: str = ""
    held: bool = False
    remove_card: bool = False


class CardBurner:
    """Copy, unmount, write, and read back one image. Paths are injectable."""

    def __init__(self, hold_path: Path = HOLD_PATH, device: Path = DEVICE,
                 microsd: str = MICROSD_MOUNT, data: str = DATA_MOUNT):
        self.hold_path = Path(hold_path)
        self.device = Path(device)
        self.microsd = microsd
        self.data = data

    def burn(self, source: Path, *, on_card: bool, progress) -> BurnResult:
        """Write ``source`` to the card. ``on_card`` copies it into RAM first."""
        copy: Path | None = None
        try:
            image = source
            if on_card:
                progress("Copying the image\u2026", 0, 1)
                image = self._copy_to_ram(source, progress)
                copy = image
            self._hold()
        except BurnError as exc:
            self._delete(copy)
            return BurnResult(False, str(exc))
        except OSError:
            self._delete(copy)
            return BurnResult(False, "The SD card could not be prepared.")
        try:
            progress("Unmounting the SD card\u2026", 0, 1)
            self._unmount_all()
        except BurnError as exc:
            self.release()
            self._delete(copy)
            return BurnResult(False, str(exc))
        except Exception:
            self.release()
            self._delete(copy)
            return BurnResult(False, "The SD card could not be unmounted.")
        try:
            self._write_and_verify(image, progress)
        except BurnError as exc:
            return BurnResult(False, str(exc), str(copy or ""), True, True)
        except Exception:
            return BurnResult(False, "The image could not be written.", str(copy or ""), True, True)
        return BurnResult(True, "The image was written.", str(copy or ""), True, True)

    def release(self) -> None:
        """Drop the hold and mount the boot partition again when it is present."""
        try:
            self.hold_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._mount_boot()

    def _copy_to_ram(self, source: Path, progress) -> Path:
        size = source.stat().st_size
        available = self._mem_available()
        if available is not None and available < size + RAM_MARGIN:
            raise BurnError("There is not enough free RAM to copy this image.")
        try:
            directory = sdcard.ram_directory("bigsigner-burn")
        except sdcard.SdError as exc:
            raise BurnError("No RAM filesystem is available.") from exc
        dest = directory / "image"
        written = 0
        try:
            with source.open("rb") as src, dest.open("wb") as dst:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    written += len(chunk)
                    progress("Copying the image\u2026", written, max(size, 1))
                dst.flush()
                os.fsync(dst.fileno())
        except OSError as exc:
            self._delete(dest)
            raise BurnError("The image could not be copied into RAM.") from exc
        return dest

    def _hold(self) -> None:
        fd = os.open(self.hold_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, b"hold\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _unmount_all(self) -> None:
        for mount in (self.microsd, self.data):
            if mount not in self._mounts():
                continue
            result = self._run(["umount", mount])
            if result.returncode != 0 or mount in self._mounts():
                raise BurnError("The SD card is still in use.")

    def _write_and_verify(self, image: Path, progress) -> None:
        size = image.stat().st_size
        if size <= 0:
            raise BurnError("This file is not a disk image.")
        if size > self._device_bytes():
            raise BurnError("This image is larger than the SD card.")
        digest = hashlib.sha256()
        written = 0
        try:
            fd = os.open(self.device, os.O_RDWR)
        except OSError as exc:
            raise BurnError("The SD card is not available.") from exc
        try:
            with image.open("rb") as src:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    view = chunk
                    while view:
                        count = os.write(fd, view)
                        if count <= 0:
                            raise BurnError("The image could not be written.")
                        view = view[count:]
                    written += len(chunk)
                    progress("Writing the image\u2026", written, size)
            os.fsync(fd)
        except BurnError:
            raise
        except OSError as exc:
            raise BurnError("The image could not be written.") from exc
        finally:
            os.close(fd)
        self._drop_caches()
        self._reread_partitions()
        check = hashlib.sha256()
        remaining = size
        read = 0
        try:
            fd = os.open(self.device, os.O_RDONLY)
        except OSError as exc:
            raise BurnError("The image on the SD card could not be read back.") from exc
        try:
            while remaining:
                chunk = os.read(fd, min(_CHUNK, remaining))
                if not chunk:
                    raise BurnError("The image on the SD card does not match the file.")
                check.update(chunk)
                remaining -= len(chunk)
                read += len(chunk)
                progress("Verifying the image\u2026", read, size)
        except BurnError:
            raise
        except OSError as exc:
            raise BurnError("The image on the SD card could not be read back.") from exc
        finally:
            os.close(fd)
        if check.digest() != digest.digest():
            raise BurnError("The image on the SD card does not match the file.")

    def _device_bytes(self) -> int:
        if self.device.is_file() and not self.device.is_block_device():
            return self.device.stat().st_size
        sysfs = Path("/sys/class/block") / self.device.name / "size"
        try:
            return int(sysfs.read_text().strip()) * 512
        except (OSError, ValueError) as exc:
            raise BurnError("The SD card is not available.") from exc

    def _drop_caches(self) -> None:
        try:
            fd = os.open("/proc/sys/vm/drop_caches", os.O_WRONLY)
        except OSError:
            return
        try:
            os.write(fd, b"3\n")
        except OSError:
            pass
        finally:
            os.close(fd)

    def _reread_partitions(self) -> None:
        try:
            self._run(["blockdev", "--rereadpt", str(self.device)])
        except OSError:
            pass

    def _mount_boot(self) -> None:
        partition = Path(f"{self.device}p1")
        sysfs = Path("/sys/class/block") / partition.name
        if not partition.exists() and not (sysfs / "dev").exists():
            return
        if self.microsd in self._mounts():
            return
        try:
            Path(self.microsd).mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        self._run(["mount", "-o", "sync,nodirty", str(partition), self.microsd])
        if self.microsd not in self._mounts():
            self._run(["mount", "-o", "sync", str(partition), self.microsd])

    def _mounts(self) -> list[str]:
        try:
            text = Path("/proc/mounts").read_text()
        except OSError:
            return []
        found = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) >= 2:
                found.append(fields[1].replace("\\040", " "))
        return found

    def _mem_available(self) -> int | None:
        try:
            text = Path("/proc/meminfo").read_text()
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1]) * 1024
        return None

    def _run(self, argv: list[str]):
        return subprocess.run(argv, capture_output=True, text=True)

    @staticmethod
    def _delete(path: Path | None) -> None:
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
