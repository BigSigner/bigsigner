"""Screenshot the external-key review and the refusals that come before it."""

from pathlib import Path

from bigsigner.slip132 import display_form, to_canonical
from bigsigner.ui.app import App
from bigsigner.ui.canvas import RED
from test_domain import ABANDON, LEGAL, expression, root_of
from test_ui import ScreenRecord

PATH_ERROR = "The derivation path is not a supported single-sig or multisig path for this network."


def _folder(name):
    return Path("artifacts/screenshots") / name


def _open_review(text, network="main"):
    app = App()
    app.session.network = network
    app.screen = "scan"
    app.scan_kind = "key"
    app.accept_qr(text)
    return app


def _open_details(text, network="main"):
    app = _open_review(text, network)
    app._act("external-next")
    assert app.screen == "external-details"
    return app


def _reveal_bottom(app):
    app.render()
    limit = app.scroll_max.get("external-details", 0)
    if limit <= 0:
        return
    app.pointer_down(240, 680)
    app.pointer_move(240, 680 - limit - 40)
    app.pointer_up(240, 680 - limit - 40)


def _testnet_expression(path):
    public = root_of(ABANDON).derive(path).to_public()
    extended = to_canonical(public.to_string(), "test")
    return f"[{root_of(ABANDON).my_fingerprint.hex()}/{path[2:]}]{extended}/<0;1>/*"


def _has_red(image):
    return any(pixel[:3] == RED for pixel in image.getdata())


def test_external_key_review_saves_screenshots():
    text = expression(ABANDON, "m/84h/0h/0h")
    app = _open_review(text)
    record = ScreenRecord(_folder("test_external_key_review_saves_screenshots"))
    record.note("Scanned a native-SegWit single-sig key expression. It is not stored yet.")
    assert app.screen == "external-review"
    assert "singlesig wallet" in app._lone_key_warning()
    assert "wallet owner must verify" in app._lone_key_warning()
    assert app.session.fingerprints == {}
    record.shot(app, "warning")
    continue_box = next(hit["box"] for hit in app.hits if hit["action"] == "external-next")
    assert continue_box[1] < 800
    assert any(hit["label"] == "Show Extended Public Key Details" for hit in app.hits)
    record.click(app, "external-next")
    assert app.screen == "external-details"
    record.shot(app, "details")
    _reveal_bottom(app)
    record.shot(app, "review-continue")
    assert next(hit["box"] for hit in app.hits if hit["action"] == "external-continue")[1] < 800
    record.click(app, "dropdown-external-format")
    record.shot(app, "format-menu")
    assert any(hit["label"] == "zpub (SLIP-132)" for hit in app.hits)
    assert any(hit["label"] == "Full Key Expression" for hit in app.hits)
    record.click(app, "dropdown-pick-external-format-slip")
    _reveal_bottom(app)
    record.shot(app, "zpub")
    assert app._external_preview(app.pending_external).startswith("zpub")
    record.click(app, "dropdown-external-format")
    record.click(app, "dropdown-pick-external-format-expression")
    _reveal_bottom(app)
    record.shot(app, "full-expression")
    preview = app._external_preview(app.pending_external)
    assert preview.startswith(f"[{root_of(ABANDON).my_fingerprint.hex()}/84h/0h/0h]xpub")
    assert preview.endswith("/<0;1>/*")
    record.click(app, "external-continue")
    record.shot(app, "external-key")
    assert app.screen == "key"
    assert app.session.wallets == []
    assert app.notice == "The watch-only key was added successfully."
    assert (record.folder / "index.html").is_file()


def test_external_details_centers_the_heading_and_greys_the_labels():
    from collections import Counter

    from PIL import ImageDraw

    from bigsigner.ui.canvas import HEADER, INK, MARGIN, MUTED, PAPER, RED, TITLE_SIZE, WIDTH, font, wrap

    app = _open_details(expression(ABANDON, "m/48h/0h/0h/2h"))
    image = app.render()
    draw = ImageDraw.Draw(image)
    face = font(TITLE_SIZE)
    line_h = TITLE_SIZE + 8
    room = WIDTH - 2 * MARGIN

    def span(picture, top):
        xs = [
            x
            for y in range(top, top + TITLE_SIZE)
            for x in range(WIDTH)
            if picture.getpixel((x, y))[:3] != PAPER
        ]
        assert xs
        return min(xs), max(xs)

    def dominant(picture, box):
        counts = Counter(
            picture.getpixel((x, y))[:3]
            for y in range(box[1], box[3])
            for x in range(box[0], box[2])
            if picture.getpixel((x, y))[:3] != PAPER
        )
        assert counts
        return counts.most_common(1)[0][0]

    y = HEADER + 16
    for _line in wrap(draw, "Extended Public Key Details", face, room):
        left, right = span(image, y)
        assert abs(left + right - WIDTH) <= 4
        y += line_h
    y += 8
    prompt = "Verify this Extended Public Key on the other hardware wallet:"
    y += line_h * len(wrap(draw, prompt, face, room))
    y += 8 + line_h + 8 + 64 + 16
    preview = app._external_preview(app.pending_external)
    y += line_h * len(wrap(draw, preview, font(TITLE_SIZE, mono=True), room))
    y += 16
    y += line_h * len(wrap(draw, "Verify these details are backed up:", face, room))
    y += 20
    app.scroll["external-details"] = max(0, y - (HEADER + 24))
    image = app.render()
    y -= app.scroll["external-details"]
    label_w = int(draw.textlength("Type: ", font=face))
    assert dominant(image, (MARGIN, y + 4, MARGIN + label_w - 4, y + TITLE_SIZE - 2)) == MUTED
    assert dominant(image, (MARGIN + label_w + 4, y + 4, MARGIN + label_w + 180, y + TITLE_SIZE - 2)) == INK
    y += line_h
    assert dominant(image, (MARGIN, y + 4, MARGIN + 140, y + TITLE_SIZE - 2)) == INK
    y += line_h
    account_w = int(draw.textlength("Account: ", font=face))
    assert dominant(image, (MARGIN, y + 4, MARGIN + account_w - 4, y + TITLE_SIZE - 2)) == MUTED
    assert dominant(image, (MARGIN + account_w + 4, y + 4, MARGIN + account_w + 160, y + TITLE_SIZE - 2)) == INK
    y += line_h
    path_w = int(draw.textlength("Derivation Path:", font=face))
    assert dominant(image, (MARGIN, y + 4, MARGIN + path_w - 4, y + TITLE_SIZE - 2)) == MUTED
    y += line_h
    assert dominant(image, (WIDTH // 2 - 50, y + 4, WIDTH // 2 + 50, y + TITLE_SIZE - 2)) == INK

    other_app = _open_details(expression(ABANDON, "m/84h/0h/7h"))
    other_app.scroll["external-details"] = app.scroll["external-details"]
    other = other_app.render()
    assert dominant(other, (MARGIN, y - 2 * line_h + 4, MARGIN + account_w - 4, y - line_h + TITLE_SIZE - 2)) == MUTED
    assert dominant(other, (MARGIN + account_w + 4, y - 2 * line_h + 4, MARGIN + account_w + 40, y - line_h - 2)) == RED
    app = _open_details(expression(ABANDON, "m/84h/0h/7h"))
    app.scroll["external-details"] = other_app.scroll["external-details"]
    record = ScreenRecord(_folder("test_external_key_nondefault_account_saves_screenshots"))
    record.note("The account is 7, so the account line is red and marked non-default.")
    image = app.render()
    record.shot(app, "account-7")
    assert _has_red(image)
    zero_app = _open_details(expression(ABANDON, "m/84h/0h/0h"))
    zero_app.scroll["external-details"] = other_app.scroll["external-details"]
    zero = zero_app.render()
    assert not _has_red(zero)


def test_multisig_external_key_format_saves_screenshots():
    app = _open_details(expression(ABANDON, "m/48h/0h/0h/2h"))
    record = ScreenRecord(_folder("test_multisig_external_key_format_saves_screenshots"))
    record.note("A multisig key expression offers Zpub as its SLIP-132 form.")
    record.shot(app, "type")
    _reveal_bottom(app)
    record.click(app, "dropdown-external-format")
    record.shot(app, "zpub-menu")
    assert any(hit["label"] == "Zpub (SLIP-132)" for hit in app.hits)
    record.click(app, "dropdown-pick-external-format-slip")
    _reveal_bottom(app)
    record.shot(app, "Zpub")
    assert app._external_preview(app.pending_external).startswith("Zpub")
    assert app._lone_key_warning() == (
        "You are about to load an External Key for a multisig wallet. "
        "Your co-signer must verify on their hardware wallet that the following "
        "extended public key (xpub) is indeed theirs."
    )


def test_taproot_external_key_format_saves_screenshots():
    app = _open_details(expression(ABANDON, "m/86h/0h/0h"))
    record = ScreenRecord(_folder("test_taproot_external_key_format_saves_screenshots"))
    record.note("Taproot has no SLIP-132 form. The menu is xpub and the full key expression.")
    record.shot(app, "type")
    _reveal_bottom(app)
    record.click(app, "dropdown-external-format")
    record.shot(app, "menu")
    labels = {hit["label"] for hit in app.hits}
    assert "xpub" in labels
    assert "Full Key Expression" in labels
    assert not any("SLIP-132" in label for label in labels)
    assert display_form(app.pending_external.canonical, "main", app.pending_external.role) is None


def test_testnet_external_key_formats_saves_screenshots():
    single = _open_details(_testnet_expression("m/84h/1h/0h"), network="test")
    record = ScreenRecord(_folder("test_testnet_external_key_formats_saves_screenshots"))
    record.note("Testnet native SegWit uses tpub, and vpub as the SLIP-132 form.")
    _reveal_bottom(single)
    record.click(single, "dropdown-external-format")
    record.shot(single, "vpub-menu")
    labels = {hit["label"] for hit in single.hits}
    assert "tpub" in labels
    assert "vpub (SLIP-132)" in labels
    multi = _open_details(_testnet_expression("m/48h/1h/0h/2h"), network="test")
    record.note("Testnet multisig uses Vpub as the SLIP-132 form.")
    _reveal_bottom(multi)
    record.click(multi, "dropdown-external-format")
    record.shot(multi, "Vpub-menu")
    assert any(hit["label"] == "Vpub (SLIP-132)" for hit in multi.hits)


def _load_key_file(app, record, folder, name, text):
    (folder / name).write_text(text + "\n")
    app.screen = "keys"
    record.click(app, "plus")
    record.click(app, "Load from SD Card")
    record.click(app, name)


def test_external_key_unsupported_path_saves_screenshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    bad = expression(ABANDON, "m/84h/0h/0h").replace("84h/0h/0h", "44h/0h/0h", 1)
    app = App()
    record = ScreenRecord(_folder("test_external_key_unsupported_path_saves_screenshots"))
    record.note("A legacy derivation path was loaded from the SD card.")
    _load_key_file(app, record, tmp_path, "bad-path.txt", bad)
    record.shot(app, "unsupported-path")
    assert app.screen == "load-error"
    assert app.load_error == PATH_ERROR
    assert app.notice == ""
    assert app.session.fingerprints == {}
    record.click(app, "OK")
    assert app.screen == "keys"


def test_external_key_duplicate_saves_screenshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    text = expression(ABANDON, "m/84h/0h/0h")
    app = App()
    app.session.commit_external_key(app.session.prepare_external_key(text))
    record = ScreenRecord(_folder("test_external_key_duplicate_saves_screenshots"))
    record.note("The same key expression was loaded again from the SD card.")
    _load_key_file(app, record, tmp_path, "again.txt", text)
    record.shot(app, "already-loaded")
    assert app.screen == "load-error"
    assert app.load_error == "This key is already loaded."
    assert len(app.session.fingerprints[root_of(ABANDON).my_fingerprint].keys) == 1
    record.click(app, "OK")
    assert app.screen == "keys"


def test_external_key_from_loaded_seed_saves_screenshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.session.add_mnemonic(ABANDON.split())
    record = ScreenRecord(_folder("test_external_key_from_loaded_seed_saves_screenshots"))
    record.note("An SD card file holds the xpub of a seed that is already loaded.")
    _load_key_file(app, record, tmp_path, "from-seed.txt", expression(ABANDON, "m/84h/0h/0h"))
    record.shot(app, "seed-already-loaded")
    nickname = next(iter(app.session.fingerprints.values())).nickname
    assert app.screen == "load-error"
    assert app.load_error == (
        f"The original seed of this external key is already loaded ({nickname}), "
        "so this external key is not needed."
    )
    assert len(next(iter(app.session.fingerprints.values())).keys) == 1
    record.click(app, "OK")
    assert app.screen == "keys"


def test_external_key_seed_mismatch_saves_screenshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.session.add_mnemonic(ABANDON.split())
    forged = expression(LEGAL, "m/84h/0h/0h").replace(
        root_of(LEGAL).my_fingerprint.hex(),
        root_of(ABANDON).my_fingerprint.hex(),
        1,
    )
    record = ScreenRecord(_folder("test_external_key_seed_mismatch_saves_screenshots"))
    record.note("An SD card file matches a loaded seed's fingerprint, but not its xpub.")
    _load_key_file(app, record, tmp_path, "forged.txt", forged)
    record.shot(app, "suspicious-xpub")
    nickname = next(iter(app.session.fingerprints.values())).nickname
    assert app.load_error == (
        f"The key claims to belong to a previously-imported seed (named {nickname}). "
        "However, its extended public key is not the one that seed derives. "
        "This is very suspicious. The odds of this happening with a real wallet, "
        "rather than a bug or malicious code, are lower than the odds of winning the lottery."
    )
    assert app.screen == "load-error"
    assert len(next(iter(app.session.fingerprints.values())).keys) == 1
    record.click(app, "OK")
    assert app.screen == "keys"


def test_sd_card_key_expression_opens_the_review_saves_screenshots(tmp_path, monkeypatch):
    text = expression(ABANDON, "m/86h/0h/3h")
    (tmp_path / "key.txt").write_text(text + "\n")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.screen = "keys"
    record = ScreenRecord(_folder("test_sd_card_key_expression_opens_the_review_saves_screenshots"))
    record.note("Loaded a taproot key expression from a file on the SD card.")
    app.render()
    record.click(app, "plus")
    record.click(app, "Load from SD Card")
    record.click(app, "key.txt")
    record.shot(app, "warning")
    assert app.screen == "external-review"
    assert app.pending_external.account == 3
    assert app.session.fingerprints == {}
    record.click(app, "external-next")
    record.shot(app, "details")
    record.click(app, "external-continue")
    assert app.screen == "key"
    assert app.session.wallets == []
