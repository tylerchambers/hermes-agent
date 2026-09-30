"""`hermes vault sources --disable` must not crash on a hand-edited non-dict
``vault:`` section in config.yaml (the same YAML-shape hazard class
``_voice_cfg_dict`` guards for voice.*, #19835): the malformed section is
coerced to a dict before the opt-out is written."""

from types import SimpleNamespace

import hermes_yaml as yaml

from agent.vault_store import VaultStore
from hermes_cli.vault import _cmd_sources, vault_command


def _corrupt_vault(home):
    store = VaultStore(home / "vault")
    store.add_item(
        "login",
        "site",
        {"identifier_type": "email", "identifier": "u", "password": "p"},
        origin="https://x.example",
    )
    store._vault_path.write_bytes(store._fernet().encrypt(b"{not json"))


def test_sources_disable_tolerates_scalar_vault_section(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text("vault: true\n")

    _cmd_sources(SimpleNamespace(enable=None, disable="bitwarden"))

    saved = yaml.safe_load((home / "config.yaml").read_text())
    assert saved["vault"]["bitwarden"]["enabled"] is False


def test_vault_command_surfaces_corrupt_store_as_clean_error(tmp_path, monkeypatch, capsys):
    """A decryptable-but-malformed vault file surfaces through the VaultError
    contract as a clean error line on every subcommand, not a traceback."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    _corrupt_vault(home)

    vault_command(SimpleNamespace())  # bare `hermes vault` -> _cmd_list

    out = capsys.readouterr().out
    assert "Error" in out
    assert "corrupted" in out


def test_edit_origin_consent_retains_clears_and_replaces(tmp_path, monkeypatch):
    from hermes_cli import vault

    store = VaultStore(tmp_path / "vault")
    meta = store.add_item(
        "login", "site",
        {"identifier_type": "email", "identifier": "user", "password": "secret"},
        origin="https://example.com",
        allowed_origins=["https://www.example.com"],
        wildcard_origins=["https://*.example.com"],
    )
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr(
        vault.getpass, "getpass",
        lambda *args: (_ for _ in ()).throw(AssertionError("Edit must not prompt for secrets")),
    )
    original = store._vault_path.read_bytes()

    def edit(answers):
        replies = iter(answers)
        monkeypatch.setattr("builtins.input", lambda prompt: next(replies))
        vault.vault_command(SimpleNamespace(_vault_handler=vault._cmd_edit, handle=meta.id))

    # Declining existing wildcard grants leaves even the encrypted bytes unchanged.
    edit(["", "", "", "n"])
    assert store._vault_path.read_bytes() == original
    # An empty exact-list response retains the alternate; '-' clears wildcards.
    edit(["", "", "-", "y"])
    saved = store.get_meta(meta.id)
    assert saved.allowed_origins == ("https://example.com", "https://www.example.com")
    assert saved.wildcard_origins == ()
    # Entered lines replace, rather than append to, the old optional list.
    edit(["", "https://login.example.net", "", "", "y"])
    assert store.get_meta(meta.id).allowed_origins == (
        "https://example.com", "https://login.example.net",
    )
    edit(["", "-", "", "y"])
    assert store.get_meta(meta.id).allowed_origins == ("https://example.com",)
