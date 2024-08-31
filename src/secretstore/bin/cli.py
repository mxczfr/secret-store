import argparse
import logging
import pathlib

from secretstore.bin.identity import add_identity_commands
from secretstore.bin.store import add_store_commands
from secretstore.agent import SSHAgent
from sqlite3 import Connection
from secretstore.ssm import SecretStoreManager


def main():
    parser = argparse.ArgumentParser(description="Secret Store cli")
    parser.add_argument("--debug", action="store_true", help="Show debug logs")
    parser.set_defaults(f=None)
    subparsers = parser.add_subparsers()

    # Identity
    identity_parser = subparsers.add_parser("identity")
    add_identity_commands(identity_parser)

    # Store
    store_parser = subparsers.add_parser("store")
    add_store_commands(store_parser)

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.debug("Debug enabled")
    else:
        logging.basicConfig(level=logging.INFO)


    dir = pathlib.Path.home() / ".local" / "secret-store"
    dir.mkdir(exist_ok=True)

    database = format(dir / "data.db")
    
    ssm = SecretStoreManager(Connection(database), SSHAgent())

    if args.f is not None:
        args.f(args, ssm)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
