"""Where SIEM credentials live. They are never in the profile file, a URL, a log, a result or a packet.

Three ways to hold a credential, chosen per connection:

* `memory`   the credential exists only in this server process. Nothing is written to disk. After a restart the connection is
             kept but marked "credentials needed". This is the default, because it is the only store that needs no extra software.
* `keyring`  the operating system's credential store (Windows Credential Manager, macOS Keychain, Secret Service), used only when the
             optional `keyring` package is installed and has a real backend. Persistent across restarts.
* `env`      the profile stores only the NAME of an environment variable; the value is read from the process environment when needed.

There is deliberately no home-made encrypted file: without a key-management service that would be a plaintext password with extra steps.
Every operation takes an `owner`: one owner can never read, replace or delete another owner's credential.
"""
import hashlib
import json
import os
import re
import threading
from abc import ABC, abstractmethod

from shakedown.integrations.base import IntegrationError

ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
SERVICE = "shakedown-integrations"


def fingerprint(secret: dict) -> str:
    """A short, non-reversible identifier that lets a person recognise which credential is saved without revealing it."""
    canonical = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()[:10]


class SecretStore(ABC):
    kind = ""
    persistent = False
    note = ""

    @abstractmethod
    def put(self, owner: str, conn_id: str, secret: dict) -> None: ...

    @abstractmethod
    def get(self, owner: str, conn_id: str) -> dict | None: ...

    @abstractmethod
    def delete(self, owner: str, conn_id: str) -> bool: ...

    def describe(self) -> dict:
        return {"kind": self.kind, "persistent": self.persistent, "note": self.note}


class MemorySecretStore(SecretStore):
    kind, persistent = "memory", False
    note = "Credentials are held in this server process only and are lost when it stops. Nothing is written to disk."

    def __init__(self):
        self._data: dict = {}
        self._lock = threading.Lock()

    def put(self, owner, conn_id, secret):
        with self._lock:
            self._data[(owner, conn_id)] = dict(secret)

    def get(self, owner, conn_id):
        with self._lock:
            value = self._data.get((owner, conn_id))
            return dict(value) if value is not None else None

    def delete(self, owner, conn_id):
        with self._lock:
            return self._data.pop((owner, conn_id), None) is not None


class KeyringSecretStore(SecretStore):
    kind, persistent = "keyring", True
    note = "Credentials are kept in the operating system's credential store."

    def __init__(self, keyring_module=None):
        self._kr = keyring_module
        if self._kr is None:
            import keyring  # optional dependency
            self._kr = keyring

    @staticmethod
    def available(keyring_module=None) -> bool:
        try:
            kr = keyring_module
            if kr is None:
                import keyring as kr
            backend = kr.get_keyring()
            name = type(backend).__module__ + "." + type(backend).__name__
            return getattr(backend, "priority", 0) > 0 and "fail" not in name.lower() and "null" not in name.lower()
        except Exception:  # aqg: top-level boundary - an unusable keyring means "not available", never a crash at start-up
            return False

    @staticmethod
    def _key(owner, conn_id):
        return f"{owner}:{conn_id}"

    def put(self, owner, conn_id, secret):
        try:
            self._kr.set_password(SERVICE, self._key(owner, conn_id), json.dumps(secret))
        except Exception:  # aqg: top-level boundary - the OS store failed; report it without the secret
            raise IntegrationError("secret_store", "the operating system credential store refused to save the credential") from None

    def get(self, owner, conn_id):
        try:
            raw = self._kr.get_password(SERVICE, self._key(owner, conn_id))
        except Exception:  # aqg: top-level boundary
            raise IntegrationError("secret_store", "the operating system credential store could not be read") from None
        return json.loads(raw) if raw else None

    def delete(self, owner, conn_id):
        try:
            self._kr.delete_password(SERVICE, self._key(owner, conn_id))
            return True
        except Exception:  # aqg: top-level boundary - deleting something already gone is fine
            return False


def choose_store(prefer: str = "auto") -> SecretStore:
    """`auto` uses the OS credential store when it really exists, otherwise memory. `memory` forces memory."""
    if prefer in ("auto", "keyring") and KeyringSecretStore.available():
        return KeyringSecretStore()
    if prefer == "keyring":
        raise IntegrationError("secret_store", "the keyring package is not installed or has no usable backend")
    return MemorySecretStore()


def resolve_env_refs(refs: dict, environ=None) -> dict:
    """{'token': 'SPLUNK_TOKEN'} -> {'token': <value>}. Names are validated; a missing variable is a named error, never a value."""
    environ = os.environ if environ is None else environ
    out = {}
    for field, name in refs.items():
        if not isinstance(name, str) or not ENV_NAME.match(name):
            raise IntegrationError("config", "an environment variable name must be capital letters, digits and underscores (for example SPLUNK_TOKEN)")
        value = environ.get(name)
        if not value:
            raise IntegrationError("auth", f"the environment variable {name} is not set in the Shakedown server's environment")
        out[field] = value
    return out
