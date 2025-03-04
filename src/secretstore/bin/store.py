import getpass
import json
from typing import TYPE_CHECKING

from secretstore.bin.utils import yes
from secretstore.exceptions import NoIdentityForStoreFound
from secretstore.store.entity import Store

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace
    from secretstore.ssm import SecretStoreManager


def new(args: "Namespace", ssm: "SecretStoreManager"):
    """
    Add a value to a store. If the store doesn't exists, create it.
    If the store exists and the specified field exists too, ask for override.

    :param args: The cli args
    :param ssm: The SecretStoreManager

    accept two args:
        - name: The name of the store
        - field: The field to create/update
        - secret: Hide the input
    """

    store = ssm.get_store(args.name)
    exists = False
    if store is None:
        store = Store(args.name, {})
    else:
        exists = True
        if args.field in store.data and not yes(f"The field '{args.field}' already exists, do you want to override it?"):
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


def list_stores(_, ssm: "SecretStoreManager"):
    """
    List owned stores

    :param _: unused args
    :param ssm: The SecretStoreManager
    """
    for store_name in ssm.list_stores_name():
        print(store_name)


def show(args: "Namespace", ssm: "SecretStoreManager"):
    """
    Show a store data.

    :param args: The cli args
    :param ssm: The SecretStoreManager

    accept two args:
        - name: The name of the store
        - json: Display as json
        - field: Print the field as raw
    """

    try:
        store = ssm.get_store(args.name)
        if store is None:
            print(f"The store '{args.name}' was not found")
            exit()

        if args.json:
            print(json.dumps(store.data))
        elif args.field:
            print(store.data[args.field])
        else:
            print(f"=== {store.name} ===")
            for key, value in store.data.items():
                print(f"{key}: {value}")
    except NoIdentityForStoreFound as e:
        print(e)
        exit(1)


def delete(args: "Namespace", ssm: "SecretStoreManager"):
    """
    Delete a store and all related guardians

    :param args: The cli args
    :param ssm: The SecretStoreManager
    accept one args:
        - name: The name of the store
    """
    try:
        # Ensure the store exists and can be decrypted by the user
        store = ssm.get_store(args.name)
        if store and yes(f"Are you sure to delete {store.name}"):
            ssm.delete_store(store)
            print("deleted")
        elif store:
            exit(0)
        else:
            print(f"The store '{args.name}' was not found")
    except NoIdentityForStoreFound as e:
        print(e)
        exit(1)


def share(args: "Namespace", ssm: "SecretStoreManager"):
    """
    Share a owned store with another identity

    :param args: The cli args
    :param ssm: The SecretStoreManager
    accept two args
        - name: The name of the store
        - fingerprint: The identity fingerprint to share the store with
    """

    identity = ssm.identity_manager.get_identity(args.fingerprint)
    if identity is None:
        print(f"The identity '{args.fingerprint}' was not found")
        exit(1)

    store = ssm.get_encrypted_store(args.name)
    if store is None:
        print(f"The store '{args.name}' was not found")
        exit(1)
    ssm.share_store(store, identity)


def add_store_commands(parser: "ArgumentParser"):
    """
    Add all store related commands to the root parser

    :param parser: The parser which all the subparsers will be added
    """
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
    show_parser.add_argument("--json", action="store_true", help="Display as json")
    show_parser.add_argument("--field", type=str, help="Print the raw field")
    show_parser.set_defaults(f=show)

    list_parser = subparsers.add_parser("list", help="List owned stores")
    list_parser.set_defaults(f=list_stores)

    delete_parser = subparsers.add_parser("rm", help="Remove a store")
    delete_parser.add_argument("name", type=str, help="The name of the store")
    delete_parser.set_defaults(f=delete)

    share_parser = subparsers.add_parser(
        "share", help="Share the store with an identity"
    )
    share_parser.add_argument("name", type=str, help="The name of the store")
    share_parser.add_argument("fingerprint", type=str, help="The identity fingerprint")
    share_parser.set_defaults(f=share)
