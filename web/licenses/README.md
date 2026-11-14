# Emulator license copies

The About section in `web/index.html` links to these local notices. They are
committed so the links work without an internet connection and do not depend on
opening the downloaded archives. License links open in a new tab to preserve the
running emulator session.

| Work | Version | Source of this copy |
| --- | --- | --- |
| Pyodide | 314.0.7 | [Upstream LICENSE](https://github.com/pyodide/pyodide/blob/314.0.7/LICENSE) |
| CPython | 3.14.2 | [Upstream LICENSE](https://github.com/python/cpython/blob/v3.14.2/LICENSE) |
| Emscripten | 5.0.3 | [Upstream LICENSE](https://github.com/emscripten-core/emscripten/blob/5.0.3/LICENSE) |
| Pillow | 12.2.0 | `pillow-12.2.0.dist-info/licenses/LICENSE` in the pinned emulator wheel |
| embit | 0.8.0 | `embit-0.8.0/LICENSE` in the pinned source archive |
| qrcode | 8.0 | `qrcode-8.0.dist-info/LICENSE` in the pinned wheel |
| jsQR | 1.4.0 | `package/LICENSE` in the [npm archive](https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz) |
| unique-names-generator word lists | Bundled data | Device notice in `src/bigsigner/licenses.py` |
| Bytewords | Bundled data | Device notice in `src/bigsigner/licenses.py` |
| DejaVu fonts | Bundled assets | Device notice in `src/bigsigner/licenses.py` |
| Font Awesome Free | Bundled font | `src/bigsigner/resources/FontAwesome-LICENSE.txt` |
| SeedSigner icons | Bundled font | `src/bigsigner/resources/seedsigner-icons.LICENSE` |

The external asset versions are pinned in `src/bigsigner/bundle.py`. The CPython
and Emscripten versions come from the pinned `pyodide-lock.json` metadata.
When updating a dependency or shared notice, refresh its copy here and the
version and link labels in Emulator Credits. Keep the upstream notice intact.

The emulator's Pillow build is newer than the device's pinned dependency, so its
notice is copied from the emulator wheel rather than from the device notice.
