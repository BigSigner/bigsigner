import pytest

from bigsigner.sdcard import unmount_memory


@pytest.fixture(autouse=True)
def _no_sd_card():
    unmount_memory()
    yield
    unmount_memory()
