"""In-memory keys and wallets. Nothing here is written to disk."""

import unicodedata

from embit import bip32, bip39
from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum
from embit.networks import NETWORKS

from .bsms import descriptor_from_bsms
from .names import animal_name
from .parse import ParseError, parse_key_expression, parse_wallet, _normalize_expression
from .paths import (
    HARDENED,
    MULTISIG_NATIVE,
    SINGLESIG_NATIVE,
    SINGLESIG_TAPROOT,
    coin_type,
    format_path,
)


class SessionError(ValueError):
    pass


class StoredKey:
    def __init__(self, kind, fingerprint, mnemonic=None, passphrase=None, path=None, xpub=None, account=None):
        self.kind = kind
        self.fingerprint = fingerprint
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.path = path
        self.xpub = xpub
        self.account = account

    @property
    def has_seed(self):
        return self.mnemonic is not None


class FingerprintRecord:
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        self.keys = []

    @property
    def nickname(self):
        return animal_name(self.fingerprint)


class WalletRecord:
    def __init__(self, role, threshold, fingerprints, accounts):
        self.role = role
        self.threshold = threshold
        # Descriptor order from the import that created this wallet. Later
        # descriptors of the same wallet do not reorder it. The wallet screen
        # and account-index tuples follow this sequence.
        self.fingerprints = tuple(fingerprints)
        self.accounts = dict(accounts)

    @property
    def multisig(self):
        return self.role == MULTISIG_NATIVE


class Session:
    def __init__(self, network="main"):
        self.network = network
        self.fingerprints = {}
        self.wallets = []
        self.passphrases = {}
        self.passphrase_counter = 0
        self.key_counter = 0

    def set_network(self, network: str):
        if network not in ("main", "test", "regtest"):
            raise SessionError("The network must be mainnet, testnet, or regtest.")
        if network == self.network:
            return "The network is already set to that value."
        self.network = network
        removed_xpub = False
        for record in self.fingerprints.values():
            kept = [key for key in record.keys if key.has_seed]
            if len(kept) != len(record.keys):
                removed_xpub = True
            record.keys = kept
        self.fingerprints = {
            fingerprint: record
            for fingerprint, record in self.fingerprints.items()
            if record.keys
        }
        removed_wallet = bool(self.wallets)
        self.wallets = []
        if removed_xpub or removed_wallet:
            return "Existing xpubs and wallets were removed. Seeds are still in memory."
        return ""

    def add_mnemonic(self, words, passphrase=None) -> dict:
        mnemonic = _clean_mnemonic(words)
        bip39.mnemonic_to_seed(" ".join(mnemonic))  # validates the checksum
        secret = "" if passphrase is None else unicodedata.normalize("NFKD", passphrase)
        if secret == "":
            kind = "seed"
            stored_passphrase = None
        else:
            kind = "seed_passphrase"
            stored_passphrase = secret
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(mnemonic), secret))
        fingerprint = root.my_fingerprint
        self._reject_seed_collision(fingerprint, mnemonic, stored_passphrase)
        self._reject_xpub_mismatches(root, fingerprint)
        removed = self._drop_xpubs(fingerprint)
        record = self._ensure_fingerprint(fingerprint)
        if stored_passphrase:
            self.passphrase_index(stored_passphrase)
        stored = self._new_key(kind, fingerprint, mnemonic, stored_passphrase)
        stored.root = root
        record.keys = [stored]
        warnings = _passphrase_warnings(stored_passphrase)
        message = "The seed was added successfully."
        if removed:
            message += " External keys derived from this seed were removed."
        return {"message": message, "warnings": warnings, "fingerprint": fingerprint}

    def add_text(self, text: str) -> dict:
        cleaned = text.strip()
        if not cleaned:
            raise SessionError("There is nothing to import.")
        try:
            wallet = parse_wallet(cleaned, self.network)
        except ParseError as wallet_error:
            try:
                key = parse_key_expression(cleaned, self.network)
            except ParseError:
                raise SessionError(str(wallet_error)) from wallet_error
            return self._add_watch_key(key)
        if wallet.multisig:
            return self._add_wallet(wallet)
        if len(wallet.keys) != 1:
            raise SessionError("A single-sig wallet must contain one key.")
        return self._add_watch_or_wallet(wallet)

    def passphrase_index(self, passphrase: str) -> int:
        """The stable number for a loaded passphrase. A new phrase gets the next number."""
        if passphrase not in self.passphrases:
            self.passphrase_counter += 1
            self.passphrases[passphrase] = self.passphrase_counter
        return self.passphrases[passphrase]

    def deletion_message(self, fingerprint: bytes, key_index: int) -> str:
        """What the confirmation dialog should say before this key is deleted."""
        record = self._record(fingerprint)
        if key_index < 0 or key_index >= len(record.keys):
            raise SessionError("That key is not loaded.")
        removed = record.keys[key_index]
        remaining = [key for key in record.keys if key is not removed]
        removed_wallets = []
        affected = []
        for wallet in self.wallets:
            if fingerprint not in wallet.fingerprints:
                continue
            if not _keys_cover_role(remaining, wallet.role):
                removed_wallets.append(wallet)
                continue
            lost = _account_lost_by_removing(wallet, fingerprint, removed, remaining)
            if lost is not None:
                affected.append((wallet, lost))
        sentences = ["Delete this key?"]
        if len(removed_wallets) == 1:
            name = self.wallet_short_name_of(removed_wallets[0])
            sentences.append(f'Wallet "{name}" depends on it and will be removed.')
        elif len(removed_wallets) > 1:
            sentences.append(f"{len(removed_wallets)} wallets depend on it and will be removed.")
        if len(affected) == 1:
            wallet, account = affected[0]
            name = self.wallet_short_name_of(wallet)
            sentences.append(
                f'Wallet "{name}" depends on it and will not be able to use account-index {account}.'
            )
        elif len(affected) > 1:
            sentences.append(
                f"{len(affected)} wallets depend on it and will not be able to use some account-indexes."
            )
        if len(sentences) == 1:
            return sentences[0]
        return " ".join(sentences)

    def delete_key(self, fingerprint: bytes, key_index: int) -> str:
        record = self._record(fingerprint)
        if key_index < 0 or key_index >= len(record.keys):
            raise SessionError("That key is not loaded.")
        removed = record.keys[key_index]
        affected = []
        for wallet in self.wallets:
            if fingerprint in wallet.fingerprints and wallet.accounts.get(fingerprint) == getattr(removed, "account", wallet.accounts.get(fingerprint)):
                affected.append(wallet)
        del record.keys[key_index]
        if not record.keys:
            del self.fingerprints[fingerprint]
        if removed.has_seed and removed.passphrase:
            self._release_passphrase(removed.passphrase)
        removed_wallets = []
        switched = False
        for wallet in list(self.wallets):
            if fingerprint not in wallet.fingerprints:
                continue
            if not self._any_account(fingerprint, wallet.role):
                self.wallets.remove(wallet)
                removed_wallets.append(wallet)
                continue
            if not self._can_use_account(fingerprint, wallet.role, wallet.accounts[fingerprint]):
                wallet.accounts[fingerprint] = self._lowest_account(fingerprint, wallet.role)
                switched = True
        if removed_wallets:
            return "The key was deleted. A wallet that can no longer be derived was deleted too."
        if switched or affected:
            return "The key was deleted. A wallet account that depended on it was changed."
        return "The key was deleted."

    def delete_wallet(self, index: int):
        if index < 0 or index >= len(self.wallets):
            raise SessionError("That wallet is not loaded.")
        del self.wallets[index]

    def set_account(self, wallet_index: int, fingerprint: bytes, account: int):
        wallet = self._wallet(wallet_index)
        if fingerprint not in wallet.fingerprints:
            raise SessionError("That key is not part of this wallet.")
        if account < 0:
            raise SessionError("The account index cannot be negative.")
        if account >= 0x80000000:
            raise SessionError("The account index is too large.")
        if not self._can_use_account(fingerprint, wallet.role, account):
            raise SessionError("That account is not available for this key.")
        wallet.accounts[fingerprint] = account

    def account_options(self, fingerprint: bytes, role: str) -> list[int] | None:
        """Account indexes this key can use. None means any index, because the seed is loaded."""
        if self._seed_for(fingerprint) is not None:
            return None
        return sorted(
            {
                key.account
                for key in self._xpubs(fingerprint)
                if getattr(key, "role", None) == role and key.account is not None
            }
        )

    def descriptor_text(self, wallet_index: int, slip132=False) -> str:
        del slip132  # exports stay canonical; the screen handles the display form
        wallet = self._wallet(wallet_index)
        return _descriptor(wallet, self)

    def addresses(self, wallet_index: int, branch: int, start: int, count: int) -> list[str]:
        wallet = self._wallet(wallet_index)
        descriptor = Descriptor.from_string(_descriptor(wallet, self))
        network = NETWORKS[_network_name(self.network)]
        return [
            descriptor.derive(index, branch_index=branch).address(network=network)
            for index in range(start, start + count)
        ]

    def find_address(self, wallet_index: int, address: str, start: int, count: int):
        for branch, label in ((0, "receive"), (1, "change")):
            for index, candidate in enumerate(
                self.addresses(wallet_index, branch, start, count), start=start
            ):
                if candidate.lower() == address.lower():
                    return {"branch": label, "index": index, "address": candidate}
        return None

    def _add_watch_key(self, key) -> dict:
        self._check_watch_key(key)
        record = self._ensure_xpub_fingerprint(key.fingerprint)
        stored = self._new_key("xpub", key.fingerprint, path=key.path, xpub=key.xpub, account=key.account)
        stored.role = key.role
        record.keys.append(stored)
        return {"message": "The watch-only key was added successfully.", "warnings": _branch_list(key), "fingerprint": key.fingerprint}

    def prepare_external_key(self, text: str):
        """Parse a key expression and refuse it when it must not be loaded. Nothing is stored."""
        try:
            key = parse_key_expression(text, self.network)
        except ParseError as exc:
            raise SessionError(str(exc)) from exc
        self._guard_external_key(key)
        return key

    def commit_external_key(self, key) -> dict:
        """Store a key expression that already passed the review screen."""
        self._guard_external_key(key)
        return self._add_watch_key(key)

    def _guard_external_key(self, key):
        for existing in self._xpubs(key.fingerprint):
            if tuple(existing.path) != tuple(key.path):
                continue
            if _same_extended(existing.xpub, key.xpub):
                raise SessionError("This key is already loaded.")
            raise SessionError(
                "A different extended key is already loaded for this fingerprint and derivation path."
            )
        seed = self._seed_for(key.fingerprint)
        if seed is None:
            return
        derived = _derive_public(seed, key.path)
        nickname = self.fingerprints[key.fingerprint].nickname
        if not _same_extended(derived, key.xpub):
            raise SessionError(
                f"The key claims to belong to a previously-imported seed (named {nickname}). "
                "However, its extended public key is not the one that seed derives. "
                "This is very suspicious. The odds of this happening with a real wallet, "
                "rather than a bug or malicious code, are lower than the odds of winning the lottery."
            )
        raise SessionError(
            f"The original seed of this external key is already loaded ({nickname}), "
            "so this external key is not needed."
        )

    def _add_watch_or_wallet(self, wallet) -> dict:
        key = wallet.keys[0]
        existing = self._wallet_by_identity(wallet)
        self._check_watch_key(key, allow_existing_same=True)
        already = self._matching_xpub(key)
        seed = self._seed_for(key.fingerprint)
        if existing and (seed or already):
            current = existing.accounts[key.fingerprint]
            raise SessionError(
                "This wallet is already loaded. "
                f"Its account is {current}. You can switch it to account {key.account}."
            )
        if existing and not seed and not already:
            self._store_xpub(key)
            existing.accounts[key.fingerprint] = key.account
            return {
                "message": (
                    f"Account {key.account} was added to the existing wallet. "
                    "You can switch to it from the wallet screen."
                ),
                "warnings": wallet.warnings,
                "fingerprint": key.fingerprint,
            }
        self._store_xpub(key)
        created = self._create_wallet(wallet)
        return {
            "message": "The wallet was added successfully.",
            "warnings": wallet.warnings,
            "wallet": created,
            "fingerprint": key.fingerprint,
        }

    def _add_wallet(self, wallet) -> dict:
        for key in wallet.keys:
            self._check_watch_key(key, allow_existing_same=True)
        existing = self._wallet_by_identity(wallet)
        if existing:
            available = all(self._key_already_known(key) for key in wallet.keys)
            phrase = account_index_phrase(
                existing.fingerprints,
                {key.fingerprint: key.account for key in wallet.keys},
            )
            name = self.wallet_short_name_of(existing)
            if available:
                raise SessionError(
                    f"{name} is already loaded. You can switch it to {phrase}."
                )
            for key in wallet.keys:
                if not self._key_already_known(key):
                    self._store_xpub(key)
            return {
                "message": f"{name} is already loaded. You can now also use {phrase}.",
                "warnings": wallet.warnings,
            }
        for key in wallet.keys:
            if not self._key_already_known(key):
                self._store_xpub(key)
        created = self._create_wallet(wallet)
        return {"message": "The multisig wallet was added successfully.", "warnings": wallet.warnings, "wallet": created}

    def _create_wallet(self, parsed):
        accounts = {key.fingerprint: key.account for key in parsed.keys}
        record = WalletRecord(
            parsed.role,
            parsed.threshold,
            [key.fingerprint for key in parsed.keys],
            accounts,
        )
        self.wallets.append(record)
        return record

    def wallet_identity(self, role, threshold, fingerprints):
        """Same wallet even if the descriptor lists keys or accounts differently.

        The key is the network, the script, the threshold, and the fingerprints
        in sorted order. Account indexes, extended keys, key order, checksums,
        and h versus ' are not part of it. sortedmulti sorts the pubkeys when
        it builds an address, so two descriptors of the same cosigners are one
        wallet even when their checksums differ.
        """
        return (self.network, role, int(threshold), tuple(sorted(fingerprints)))

    def wallet_identity_text(self, role, threshold, fingerprints) -> str:
        """A readable form of wallet_identity. It is not parsed back into a wallet."""
        coin = "0h" if self.network == "main" else "1h"
        names = sorted(fingerprint.hex() for fingerprint in fingerprints)
        if role == SINGLESIG_NATIVE:
            return f"wpkh([{names[0]}/84h/{coin}/*h]/<0;1>/*)"
        if role == SINGLESIG_TAPROOT:
            return f"tr([{names[0]}/86h/{coin}/*h]/<0;1>/*)"
        terms = ",".join(f"[{name}/48h/{coin}/*h/2h]/<0;1>/*" for name in names)
        return f"wsh(sortedmulti({int(threshold)},{terms}))"

    def wallet_short_name(self, role, threshold, fingerprints) -> str:
        """A short label for messages. Multisig uses hex, not the long animal name."""
        if role != MULTISIG_NATIVE:
            kind = "Taproot" if role == SINGLESIG_TAPROOT else "Native-Segwit"
            return f"{animal_name(fingerprints[0])} {kind}"
        hexes = ",".join(fingerprint.hex() for fingerprint in fingerprints)
        return f"{int(threshold)}-of-{len(fingerprints)} {hexes}"

    def wallet_short_name_of(self, wallet) -> str:
        return self.wallet_short_name(wallet.role, wallet.threshold, wallet.fingerprints)

    def _wallet_by_identity(self, parsed):
        wanted = self.wallet_identity(parsed.role, parsed.threshold, [key.fingerprint for key in parsed.keys])
        for wallet in self.wallets:
            identity = self.wallet_identity(wallet.role, wallet.threshold, wallet.fingerprints)
            if identity == wanted:
                return wallet
        return None

    def plan_wallet_import(self, text: str) -> dict:
        """Classify a descriptor without storing it."""
        parsed = self._parse_supported_descriptor(text)
        new_keys = []
        for key in parsed.keys:
            if self._import_key_status(key) == "new":
                new_keys.append(key)
        return {"parsed": parsed, "new_keys": new_keys, "existing": self._wallet_by_identity(parsed)}

    def apply_wallet_plan(self, plan) -> WalletRecord:
        """Store the new keys, then create the wallet or switch its accounts."""
        for key in plan["new_keys"]:
            self._store_xpub(key)
        parsed = plan["parsed"]
        existing = plan["existing"]
        if existing is None:
            existing = self._wallet_by_identity(parsed)
        if existing is not None:
            for key in parsed.keys:
                existing.accounts[key.fingerprint] = key.account
            return existing
        return self._create_wallet(parsed)

    def load_descriptor_now(self, text: str) -> dict:
        """Import a descriptor immediately. Boot uses this. A bad key still raises."""
        raw = text.strip()
        if raw.upper().startswith("BSMS"):
            try:
                raw = descriptor_from_bsms(raw, self.network)
            except ParseError as exc:
                raise SessionError(str(exc)) from exc
        plan = self.plan_wallet_import(raw)
        wallet = self.apply_wallet_plan(plan)
        if plan["existing"] is not None and plan["new_keys"]:
            message = "The wallet was already loaded. Its new account keys were added."
        elif plan["existing"] is not None:
            message = "The wallet is already loaded."
        elif plan["parsed"].multisig:
            message = "The multisig wallet was added successfully."
        else:
            message = "The wallet was added successfully."
        return {
            "message": message,
            "warnings": plan["parsed"].warnings,
            "wallet": wallet,
            "fingerprint": plan["parsed"].keys[0].fingerprint,
        }

    def _parse_supported_descriptor(self, text: str):
        payload = " ".join(text.strip().split())
        if not payload:
            raise SessionError("This wallet descriptor is empty.")
        if payload.startswith("cHNidP") or payload.lower().startswith("psbt"):
            raise SessionError("This is a transaction, not a wallet descriptor.")
        words = payload.split()
        if len(words) in (12, 18, 24) or payload.isdigit():
            raise SessionError("This is a seed, not a wallet descriptor.")
        normalized = _normalize_expression(payload).split("#", 1)[0]
        if normalized.startswith("["):
            raise SessionError("This is a key expression, not a wallet descriptor.")
        if not normalized.startswith(("wpkh(", "tr(", "wsh(", "sh(", "pkh(", "pk(", "musig(")):
            raise SessionError("This wallet descriptor is not recognized.")
        try:
            return parse_wallet(payload, self.network)
        except ParseError as exc:
            message = str(exc)
            if "same fingerprint" in message:
                raise SessionError(message) from exc
            raise SessionError(f"This wallet descriptor is not supported. {message}") from exc

    def _import_key_status(self, key) -> str:
        """Return "known" or "new". A contradictory extended key raises."""
        seed = self._seed_for(key.fingerprint)
        if seed is not None:
            derived = _derive_public(seed, key.path)
            if not _same_extended(derived, key.xpub):
                nickname = self.fingerprints[key.fingerprint].nickname
                raise SessionError(
                    f"The key claims to belong to a previously-imported seed (named {nickname}). "
                    "However, its extended public key is not the one that seed derives. "
                    "This is very suspicious. The odds of this happening with a real wallet, "
                    "rather than a bug or malicious code, are lower than the odds of winning the lottery."
                )
            return "known"
        for existing in self._xpubs(key.fingerprint):
            if tuple(existing.path) != tuple(key.path):
                continue
            if _same_extended(existing.xpub, key.xpub):
                return "known"
            raise SessionError(
                "A different extended key is already loaded for this fingerprint and derivation path."
            )
        return "new"

    def _check_watch_key(self, key, allow_existing_same=False):
        seed = self._seed_for(key.fingerprint)
        if seed is not None:
            derived = _derive_public(seed, key.path)
            if not _same_extended(derived, key.xpub):
                raise SessionError(
                    "A seed with this fingerprint is loaded, and it does not derive this extended key."
                )
            if not allow_existing_same:
                raise SessionError("This key is already available from the loaded seed.")
            return
        for existing in self._xpubs(key.fingerprint):
            if existing.path == key.path:
                if _same_extended(existing.xpub, key.xpub):
                    if allow_existing_same:
                        return
                    raise SessionError("This key is already loaded.")
                raise SessionError(
                    "A different extended key is already loaded for this fingerprint and derivation path."
                )

    def _key_already_known(self, key) -> bool:
        if self._seed_for(key.fingerprint) is not None:
            return True
        return self._matching_xpub(key) is not None

    def _matching_xpub(self, key):
        for existing in self._xpubs(key.fingerprint):
            if existing.path == key.path and _same_extended(existing.xpub, key.xpub):
                return existing
        return None

    def _store_xpub(self, key):
        if self._seed_for(key.fingerprint) is not None or self._matching_xpub(key):
            return
        record = self._ensure_xpub_fingerprint(key.fingerprint)
        stored = self._new_key("xpub", key.fingerprint, path=key.path, xpub=key.xpub, account=key.account)
        stored.role = key.role
        record.keys.append(stored)

    def _new_key(self, kind, fingerprint, mnemonic=None, passphrase=None, path=None, xpub=None, account=None):
        """A stored key tagged with the next global creation number."""
        self.key_counter += 1
        key = StoredKey(kind, fingerprint, mnemonic, passphrase, path, xpub, account)
        key.added = self.key_counter
        return key

    def _reject_seed_collision(self, fingerprint, mnemonic, passphrase):
        for key in self._seeds(fingerprint):
            if key.mnemonic == mnemonic and key.passphrase == passphrase:
                raise SessionError("This seed is already loaded.")
            raise SessionError(
                "A different seed with this fingerprint is already loaded. "
                "The new seed was not added."
            )

    def _reject_xpub_mismatches(self, root, fingerprint):
        for key in self._xpubs(fingerprint):
            derived = root.derive(format_path(list(key.path))).to_public()
            if not _same_extended(derived, key.xpub):
                raise SessionError(
                    "A watch-only key with this fingerprint does not match this seed. "
                    "The seed was not added."
                )

    def _drop_xpubs(self, fingerprint) -> int:
        record = self.fingerprints.get(fingerprint)
        if record is None:
            return 0
        before = len(record.keys)
        record.keys = [key for key in record.keys if key.has_seed]
        return before - len(record.keys)

    def _ensure_fingerprint(self, fingerprint):
        record = self.fingerprints.get(fingerprint)
        if record is not None:
            return record
        record = FingerprintRecord(fingerprint)
        self.fingerprints[fingerprint] = record
        return record

    def _ensure_xpub_fingerprint(self, fingerprint):
        return self._ensure_fingerprint(fingerprint)

    def _release_passphrase(self, passphrase: str):
        for record in self.fingerprints.values():
            if any(key.has_seed and key.passphrase == passphrase for key in record.keys):
                return
        self.passphrases.pop(passphrase, None)

    def seed_summary(self, key) -> str:
        word = key.mnemonic[0]
        titled = word[:1].upper() + word[1:]
        summary = f"{titled}..."
        if key.passphrase:
            summary += f" + Passphrase{self.passphrase_index(key.passphrase)}"
        return summary

    def generated_from(self, key) -> str:
        count = len(key.mnemonic)
        if key.passphrase:
            return f"Generated from a {count} words seed + passphrase{self.passphrase_index(key.passphrase)}."
        return f"Generated from a {count} words seed."

    def _record(self, fingerprint):
        record = self.fingerprints.get(fingerprint)
        if record is None:
            raise SessionError("That fingerprint is not loaded.")
        return record

    def _wallet(self, index):
        if index < 0 or index >= len(self.wallets):
            raise SessionError("That wallet is not loaded.")
        return self.wallets[index]

    def _seeds(self, fingerprint):
        record = self.fingerprints.get(fingerprint)
        if record is None:
            return []
        return [key for key in record.keys if key.has_seed]

    def _xpubs(self, fingerprint):
        record = self.fingerprints.get(fingerprint)
        if record is None:
            return []
        return [key for key in record.keys if not key.has_seed]

    def _seed_for(self, fingerprint):
        seeds = self._seeds(fingerprint)
        return seeds[0] if seeds else None

    def _can_use_account(self, fingerprint, role, account) -> bool:
        if self._seed_for(fingerprint) is not None:
            return True
        for key in self._xpubs(fingerprint):
            if getattr(key, "role", None) == role and key.account == account:
                return True
        return False

    def _wallet_has_any_account(self, wallet) -> bool:
        return all(
            self._can_use_account(fingerprint, wallet.role, wallet.accounts[fingerprint])
            or self._any_account(fingerprint, wallet.role)
            for fingerprint in wallet.fingerprints
        )

    def _lowest_account(self, fingerprint, role) -> int:
        if self._seed_for(fingerprint) is not None:
            return 0
        accounts = [
            key.account
            for key in self._xpubs(fingerprint)
            if getattr(key, "role", None) == role
        ]
        return min(accounts)

    def _any_account(self, fingerprint, role) -> bool:
        if self._seed_for(fingerprint) is not None:
            return True
        return any(getattr(key, "role", None) == role for key in self._xpubs(fingerprint))

    def _wallets_lost_by_removing(self, key):
        lost = []
        for wallet in self.wallets:
            if key.fingerprint not in wallet.fingerprints:
                continue
            remaining = [
                item
                for item in self.fingerprints[key.fingerprint].keys
                if item is not key and (item.has_seed or getattr(item, "role", None) == wallet.role)
            ]
            if not remaining:
                lost.append(wallet)
        return lost


def _keys_cover_role(keys, role: str) -> bool:
    if any(key.has_seed for key in keys):
        return True
    return any(getattr(key, "role", None) == role for key in keys)


def _keys_cover_account(keys, role: str, account: int) -> bool:
    if any(key.has_seed for key in keys):
        return True
    return any(
        getattr(key, "role", None) == role and key.account == account
        for key in keys
        if not key.has_seed
    )


def _account_lost_by_removing(wallet, fingerprint: bytes, removed, remaining):
    """The account index this wallet can no longer use, if another account remains."""
    if not _keys_cover_role(remaining, wallet.role):
        return None
    if removed.has_seed:
        current = wallet.accounts[fingerprint]
        if not _keys_cover_account(remaining, wallet.role, current):
            return current
        return None
    if getattr(removed, "role", None) != wallet.role:
        return None
    if _keys_cover_account(remaining, wallet.role, removed.account):
        return None
    return removed.account


def _clean_mnemonic(words) -> list[str]:
    if isinstance(words, str):
        parts = words.replace(",", " ").split()
    else:
        parts = list(words)
    parts = [unicodedata.normalize("NFKD", word).lower() for word in parts]
    if len(parts) not in (12, 18, 24):
        raise SessionError("A seed must be 12, 18, or 24 words.")
    try:
        bip39.mnemonic_to_bytes(" ".join(parts))
    except Exception as exc:
        raise SessionError("The seed checksum is not valid.") from exc
    return parts


def _passphrase_warnings(passphrase):
    if passphrase is None:
        return []
    warnings = []
    if len(passphrase) > 100 or any(ord(char) < 32 or ord(char) > 126 for char in passphrase):
        warnings.append("Another wallet may not reproduce this passphrase.")
    if passphrase[:1] == " " or passphrase[-1:] == " ":
        warnings.append("This passphrase starts or ends with a space. Another wallet may not reproduce it.")
    return warnings


def _seed_root(seed_key):
    """The master key for this seed, stretched once and kept in memory."""
    root = getattr(seed_key, "root", None)
    if root is None:
        root = bip32.HDKey.from_seed(
            bip39.mnemonic_to_seed(" ".join(seed_key.mnemonic), seed_key.passphrase or "")
        )
        seed_key.root = root
    return root


def _derive_public(seed_key, path):
    return _seed_root(seed_key).derive(format_path(list(path))).to_public()


def _same_extended(left, right) -> bool:
    return (
        left.chain_code == right.chain_code
        and left.key.sec() == right.key.sec()
        and left.depth == right.depth
        and left.child_number == right.child_number
    )


def account_index_phrase(order, accounts_by_fingerprint) -> str:
    """Account indexes in the wallet's saved fingerprint order.

    Zero is the default account. Any other index is marked non-default.
    """
    values = [_account_index_label(accounts_by_fingerprint[fingerprint]) for fingerprint in order]
    if len(values) == 1:
        return f"account-index {values[0]}"
    return f"account-indexes {','.join(values)}"


def _account_index_label(account) -> str:
    note = "default" if int(account) == 0 else "non-default"
    return f"{account} ({note})"


def _branch_list(key):
    if key.branch_note == "receive_only":
        return ["The import named only receive addresses. Change addresses were assumed as well."]
    if key.branch_note == "change_only":
        return ["The import named only change addresses. Change and receive addresses were both kept."]
    return []


def _network_name(network: str) -> str:
    if network == "main":
        return "main"
    if network == "regtest":
        return "regtest"
    return "test"


def _descriptor(wallet: WalletRecord, session: Session) -> str:
    parts = []
    for fingerprint in wallet.fingerprints:
        key = _public_for(session, fingerprint, wallet.role, wallet.accounts[fingerprint])
        origin = format_path(list(key.path))[2:]
        parts.append(f"[{fingerprint.hex()}/{origin}]{key.xpub.to_string()}/<0;1>/*")
    if wallet.role == SINGLESIG_NATIVE:
        body = f"wpkh({parts[0]})"
    elif wallet.role == SINGLESIG_TAPROOT:
        body = f"tr({parts[0]})"
    else:
        body = f"wsh(sortedmulti({wallet.threshold},{','.join(parts)}))"
    return f"{body}#{checksum(body)}"


def _public_for(session: Session, fingerprint: bytes, role: str, account: int):
    seed = session._seed_for(fingerprint)
    if seed is not None:
        path = _account_path(session.network, role, account)
        public = _derive_public(seed, path)
        public.role = role
        stored = StoredKey("derived", fingerprint, path=tuple(path), xpub=public, account=account)
        stored.role = role
        return stored
    for key in session._xpubs(fingerprint):
        if getattr(key, "role", None) == role and key.account == account:
            return key
    raise SessionError("That account is not available for this key.")


def _account_path(network: str, role: str, account: int):
    coin = coin_type(network) | HARDENED
    account_h = account | HARDENED
    if role == SINGLESIG_NATIVE:
        return [84 | HARDENED, coin, account_h]
    if role == SINGLESIG_TAPROOT:
        return [86 | HARDENED, coin, account_h]
    if role == MULTISIG_NATIVE:
        return [48 | HARDENED, coin, account_h, 2 | HARDENED]
    raise SessionError("That script type is not supported.")
