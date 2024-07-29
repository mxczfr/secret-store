from sqlite3 import Connection
from typing import TYPE_CHECKING

from paramiko.agent import Agent
from secretstore.agent import SSHAgent
from secretstore.identity.manager import IdentityManager
from secretstore.dao import IdentityDAO

if TYPE_CHECKING:
    from argparse import ArgumentParser
from secretstore import SecretStoreManager, Store

ssh_agent = SSHAgent.init()
im = IdentityManager(IdentityDAO(Connection("identities.db")))


def list_identities(args):
    if args.all:
        ids = im.get_identities()
    else:
        ids = im.get_identities_based_ssh_agent(ssh_agent)
    for i in ids:
        print(i)


def create_identities(_):
    im.create_identities(ssh_agent)


def add_identity_commands(parser: "ArgumentParser"):
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser("create")
    create_parser.set_defaults(f=create_identities)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument(
        "--all",
        action="store_true",
        help="List all identities instead of owned ones only",
    )
    list_parser.set_defaults(f=list_identities)
