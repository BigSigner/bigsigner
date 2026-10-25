"""Device entry point.

BigSigner OS runs this file with ``python3 main.py`` from the ``src`` directory,
both for the image at ``/opt/src`` and for a checkout synced to
``/mnt/data/seedsigner``. The package next to this file is what that process imports.
"""

from bigsigner.__main__ import main

if __name__ == "__main__":
    main()
