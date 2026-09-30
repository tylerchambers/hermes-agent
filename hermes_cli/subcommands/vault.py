"""``hermes vault`` subcommand parser."""

from __future__ import annotations


def build_vault_parser(subparsers) -> None:
    """Attach the local encrypted autofill vault subcommand."""
    vault_parser = subparsers.add_parser(
        "vault",
        help="Manage the local encrypted autofill vault (add/list/edit/rm credentials)",
        description=(
            "Store login credentials in a locally encrypted vault. The agent "
            "sees handles and login identifiers (metadata); passwords are "
            "injected server-side by browser_vault_fill only on explicitly saved "
            "exact origins or opt-in HTTPS subdomain wildcards and never enter "
            "the conversation. Edit origin permissions without re-entering secrets."
        ),
    )
    from hermes_cli.vault import register_cli, vault_command

    register_cli(vault_parser)
    vault_parser.set_defaults(func=vault_command)
