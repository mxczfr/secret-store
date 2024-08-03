from sqlite3 import Connection
from typing import TYPE_CHECKING
import getpass

from secretstore.agent import SSHAgent
from secretstore.bin.utils import yes
from secretstore.exceptions import NoIdentityForStoreFound
from secretstore.ssm import SecretStoreManager
from secretstore.store.entity import Store

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace


def new(args: "Namespace"):
    """
    Add a value to a store. If the store doesn't exists, create it.

    :param args: The cli args
    """
    ssm = SecretStoreManager(Connection("identities.db"), SSHAgent.init())
    
    store = ssm.get_store(args.name)
    exists = False
    if store is None:
        store = Store(args.name, {})
    else:
        if args.field in store.data and yes(f"The field '{args.field}' already exists, do you want to override it?"):
            exists = True 
        else:
            exit(0)
            
    message = f"Set {args.field} value: "
    if args.secret:
        value = getpass.getpass(message)
    else:
        value = input(message)

    store.data[args.field] = value

    if exists:
        ssm.update_store(store)
    else:
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

    new_parser = subparsers.add_parser("new", help="Create a new store")
    new_parser.add_argument("name", help="The name of the store")
    new_parser.add_argument("field", help="Set a specific field")
    new_parser.add_argument(
        "-s", "--secret", action="store_true", help="Do not display the value"
    )

    new_parser.set_defaults(f=new)

    show_parser = subparsers.add_parser("show", help="Show the store data")
    show_parser.add_argument("name", type=str, help="The name of the store")
    show_parser.set_defaults(f=show)
