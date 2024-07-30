from typing import TYPE_CHECKING

from secretstore.ssm import SecretStoreManager
from secretstore.agent import SSHAgent
from sqlite3 import Connection

from secretstore.store.entity import Store

if TYPE_CHECKING:
    from argparse import ArgumentParser


def new(args):
    ssm = SecretStoreManager(Connection("identities.db"), SSHAgent.init())
    store = Store("test", {"prout": "samantha"})
    ssm.new_store(store)


def add_store_commands(parser: "ArgumentParser"):
    subparsers = parser.add_subparsers()
    
    new_parser = subparsers.add_parser("new")
    new_parser.set_defaults(f=new)

