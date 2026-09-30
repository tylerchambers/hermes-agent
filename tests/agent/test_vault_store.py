"""``VaultStore._read_all`` must surface every decryptable-but-malformed vault
file as ``VaultError`` so callers that catch ``VaultError`` (the ``hermes vault``
commands, ``vault.*`` RPC handlers) get the designed error path instead of a raw
traceback. Corruption arrives via partial-write survivors, manual edits of the
envelope, or format drift."""

import pytest

from agent.vault_store import VaultError, VaultStore


def _corrupt(store: VaultStore, payload: bytes) -> None:
    store._vault_path.write_bytes(store._fernet().encrypt(payload))


def _store(tmp_path) -> VaultStore:
    store = VaultStore(tmp_path / "vault")
    store.add_item(
        "login",
        "Example login",
        {"identifier_type": "email", "identifier": "u@example.com", "password": "pw"},
        origin="https://example.com",
    )
    return store


@pytest.mark.parametrize(
    "op",
    ["list_items", "get_meta", "remove_item", "resolve_secret", "add_item", "update_origin_rules"],
)
def test_corrupt_vault_raises_vault_error_on_every_reader(tmp_path, op):
    """Every ``_read_all`` consumer must see the same VaultError contract so
    callers that catch VaultError all get the designed error path."""
    store = _store(tmp_path)
    _corrupt(store, b"{not json")
    call = {
        "list_items": lambda: store.list_items(),
        "get_meta": lambda: store.get_meta("vault_x"),
        "remove_item": lambda: store.remove_item("vault_x"),
        "resolve_secret": lambda: store.resolve_secret("vault_x"),
        "update_origin_rules": lambda: store.update_origin_rules(
            "vault_x", origin="https://example.com", allowed_origins=[], wildcard_origins=[],
        ),
        "add_item": lambda: store.add_item(
            "login",
            "x",
            {"identifier_type": "email", "identifier": "u", "password": "p"},
            origin="https://x.example",
        ),
    }[op]
    with pytest.raises(VaultError):
        call()


def test_login_rule_lifecycle_preserves_credentials_and_refuses_invalid_edits(tmp_path):
    store = VaultStore(tmp_path / "vault")
    meta = store.add_item(
        "login", "Example", {"identifier_type": "email", "identifier": "u@example.com",
                             "password": "synthetic-password", "otp_secret": "jbsw-y3dp"},
        "https://example.com", allowed_origins=["https://EXAMPLE.com:443", "https://www.example.com"],
    )
    original = store._read_all()[0]
    assert meta.allowed_origins == ("https://example.com", "https://www.example.com")
    updated = store.update_origin_rules(
        meta.id, origin="https://other.net", allowed_origins=["https://example.com"],
        wildcard_origins=["https://*.example.com"],
    )
    assert updated.wildcard_origins == ("https://*.example.com",)
    assert set(updated.allowed_origins) == {"https://other.net", "https://example.com"}
    for field in ("id", "created_at", "label", "identifier", "identifier_type", "secret"):
        assert store._read_all()[0][field] == original[field]
    before = store._vault_path.read_bytes()
    for kwargs in (
        {"origin": "https://*.example.com", "allowed_origins": [], "wildcard_origins": []},
        {"origin": "https://example.com", "allowed_origins": {}, "wildcard_origins": []},
        {"origin": "https://example.com", "allowed_origins": [], "wildcard_origins": ["https://*.com"]},
    ):
        with pytest.raises(VaultError):
            store.update_origin_rules(meta.id, **kwargs)
        assert store._vault_path.read_bytes() == before
    cleared = store.update_origin_rules(
        meta.id, origin=meta.origin, allowed_origins=[], wildcard_origins=[],
    )
    assert cleared.allowed_origins == (meta.origin,)
    assert cleared.wildcard_origins == ()
    legacy = store._read_all()
    del legacy[0]["allowed_origins"]
    del legacy[0]["wildcard_origins"]
    store._write_all(legacy)
    before = store._vault_path.read_bytes()
    assert store.get_meta(meta.id).allowed_origins == (meta.origin,)
    assert store.get_meta(meta.id).wildcard_origins == ()
    assert store._vault_path.read_bytes() == before
    for malformed in (None, "https://example.com", {}, [None], []):
        legacy[0]["allowed_origins"] = malformed
        store._write_all(legacy)
        with pytest.raises(VaultError):
            store.list_items()
