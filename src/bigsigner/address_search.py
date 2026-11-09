"""Bounded account planning and interruptible searches of loaded wallets."""

from itertools import product

from embit.descriptor import Descriptor
from embit.descriptor.arguments import AllowedDerivation, Key, KeyOrigin, Number
from embit.descriptor.miniscript import Sortedmulti
from embit.script import Script

from .paths import HARDENED, MULTISIG_NATIVE, SINGLESIG_NATIVE, SINGLESIG_TAPROOT
from .session import SessionError, _public_for

MAX_INDEX = HARDENED - 1
MAX_CREATORS = 512
_ROLES = {"p2wpkh": SINGLESIG_NATIVE, "p2wsh": MULTISIG_NATIVE, "p2tr": SINGLESIG_TAPROOT}


class AddressSearch:
    """Each step prepares one branch descriptor or checks one address.

    Hosts poll input between steps. Account and branch derivations are cached;
    searching an index derives only the final, non-hardened child of each key.
    """

    def __init__(self, session, address, account_start, account_end, address_start=0, address_end=MAX_INDEX):
        if not 0 <= account_start <= account_end <= MAX_INDEX:
            raise SessionError(f"Account indexes must be between 0 and {MAX_INDEX}, with the end at least the start.")
        if not 0 <= address_start <= address_end <= MAX_INDEX:
            raise SessionError(f"Address indexes must be between 0 and {MAX_INDEX}.")
        try:
            target = Script.from_address(address)
        except Exception as exc:
            raise SessionError("This address is not valid.") from exc
        role = _ROLES.get(target.script_type())
        if role is None:
            raise SessionError("No supported loaded wallets match this address type.")
        self.session = session
        self.address = address
        self.target = target.data
        self.address_index = address_start
        self.last_index = None
        self.address_end = address_end
        self.phase = "preparing"
        self.done = False
        self.result = None
        self.creator_count = 0
        self.creators = []
        self._plans = []
        for wallet_index, wallet in enumerate(session.wallets):
            if wallet.role != role:
                continue
            choices = []
            combinations = 1
            for fingerprint in wallet.fingerprints:
                options = session.account_options(fingerprint, wallet.role)
                if options is None:
                    available = range(account_start, account_end + 1)
                    # The full non-hardened range exceeds len() on a 32-bit Pi.
                    count = account_end - account_start + 1
                else:
                    available = tuple(account for account in options if account_start <= account <= account_end)
                    count = len(available)
                choices.append(available)
                combinations *= count
            self.creator_count += 2 * combinations
            if combinations:
                self._plans.append((wallet_index, wallet, choices))
        if self.creator_count > MAX_CREATORS:
            if account_start == account_end:
                raise SessionError("There are too many loaded wallets to search.")
            raise SessionError("The account-index range is too large. Choose a smaller range.")
        if not self.creator_count:
            raise SessionError("No loaded wallets can search this address type in the selected account-index range.")
        self._work = self._iterate()

    def step(self):
        if self.done:
            return
        try:
            next(self._work)
        except StopIteration as finished:
            self.result = finished.value
            self.done = True

    def close(self):
        self._work.close()
        self.creators.clear()
        self._plans.clear()
        self.done = True

    def _iterate(self):
        accounts_cache = {}
        branches_cache = {}
        for wallet_index, wallet, choices in self._plans:
            # The cap was checked before product copies any account ranges.
            for indexes in product(*choices):
                for branch in (0, 1):
                    keys = []
                    for fingerprint, account in zip(wallet.fingerprints, indexes):
                        account_key = (fingerprint, wallet.role, account)
                        if account_key not in accounts_cache:
                            accounts_cache[account_key] = _public_for(self.session, fingerprint, wallet.role, account)
                        stored = accounts_cache[account_key]
                        branch_key = (*account_key, branch)
                        if branch_key not in branches_cache:
                            branches_cache[branch_key] = stored.xpub.derive([branch])
                        # Without an origin, embit derives an extra child(0) on
                        # every Key.derive() just to construct its KeyOrigin.
                        origin = KeyOrigin(fingerprint, list(stored.path) + [branch])
                        keys.append(Key(branches_cache[branch_key], origin=origin, derivation=AllowedDerivation([None])))
                    if wallet.multisig:
                        creator = Descriptor(miniscript=Sortedmulti(Number(wallet.threshold), *keys))
                    else:
                        creator = Descriptor(key=keys[0], wsh=False, taproot=wallet.role == SINGLESIG_TAPROOT)
                    self.creators.append((wallet_index, wallet, indexes, branch, creator))
                    yield
        self.phase = "searching"
        while self.address_index <= self.address_end:
            for wallet_index, wallet, indexes, branch, creator in self.creators:
                matches = creator.derive(self.address_index).script_pubkey().data == self.target
                self.last_index = self.address_index
                if matches:
                    return {
                        "wallet_index": wallet_index,
                        "account_indexes": list(indexes),
                        "branch": branch,
                        "index": self.address_index,
                        "address_index": self.address_index,
                        "address": self.address,
                    }
                yield
            if self.address_index == self.address_end:
                return
            self.address_index += 1
