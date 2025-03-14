from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace
    from secretstore.ssm import SecretStoreManager


def list_identities(args: "Namespace", ssm: "SecretStoreManager"):
    """
    List all available identities. Per default, only owned ones are listed.
    if args.all is True, list all identities.

    :param args: The cli args
    """
    if args.all:
        ids = list(ssm.identity_manager.get_identities())
    else:
        ids = list(ssm.identity_manager.get_identities_based_ssh_agent())

    if len(ids) == 0:
        print("No identity was found. Sync identities with secret-store identity sync")

    for i in ids:
        print(i.fingerprint)


def create_identities(_, ssm: "SecretStoreManager"):
    """
    Create identities for each compatible ssh keys found via the ssh agent.
    If an identity already exists, do nothing for that key.
    """

    fingerprints = ssm.identity_manager.create_identities()
    if len(fingerprints) == 0:
        print("No identity created")
    else:
        for fingerprint in fingerprints:
            print(f"Created: {fingerprint}")


def add_identity_commands(parser: "ArgumentParser"):
    """
    Add all identity related commands to the root parser

    :param parser: The parser which all the subparsers will be added
    """
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser(
        "sync", help="Create missing identities for available ssh keys"
    )
    create_parser.set_defaults(f=create_identities)

    list_parser = subparsers.add_parser("list", help="List identities")
    list_parser.add_argument(
        "--all",
        action="store_true",
        help="List all identities instead of owned ones only",
    )
    list_parser.set_defaults(f=list_identities)
