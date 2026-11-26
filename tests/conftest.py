import pytest

from bigsigner.i18n import reset_language
from bigsigner.sdcard import unmount_memory


@pytest.fixture(autouse=True)
def _no_sd_card():
    unmount_memory()
    reset_language()
    yield
    unmount_memory()
    reset_language()
