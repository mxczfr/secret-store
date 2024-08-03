from sqlite3 import Connection
from typing import TYPE_CHECKING

from secretstore.agent import SSHAgent
from secretstore.exceptions import NoIdentityForStoreFound
from secretstore.ssm import SecretStoreManager
from secretstore.store.entity import Store

if TYPE_CHECKING:
    from argparse import ArgumentParser


def new(_):
    ssm = SecretStoreManager(Connection("identities.db"), SSHAgent.init())
    store = Store("test", {"prout": "samantha"})
    ssm.new_store(store)


def show(args):
    ssm = SecretStoreManager(Connection("identities.db"), SSHAgent.init())
    try:
        store = ssm.get_store(args.name)
        if store:
            print(store)
        else:
            print(f"The store '{args.name}' was not found")
    except NoIdentityForStoreFound as e:
        print(e)


def add_store_commands(parser: "ArgumentParser"):
    subparsers = parser.add_subparsers()

    new_parser = subparsers.add_parser("new")
    new_parser.set_defaults(f=new)

    show_parser = subparsers.add_parser("show")
    show_parser.add_argument("name", type=str, help="The name of the store")
    show_parser.set_defaults(f=show)
