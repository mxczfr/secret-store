import argparse
import getpass
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable

from secretstore import SecretStoreManager, Store

secret_store_manager = SecretStoreManager()


def _gracefully_exist_if_not_found(function: "Callable") -> "Callable":
    """
    Wrapper that gracefully exit when a File Not Found error is raised
    :param function: The function to wrap
    :return: The wrapped function
    """

    def wrapped_function(*args, **kwargs):
        try:
            function(*args, **kwargs)
        except FileNotFoundError as e:
            print(e)
            exit(1)

    return wrapped_function


def _verify_store_name(function: "Callable") -> "Callable":
    """
    Verify if the store name passed as args is valid
    :param function: The function to wrap
    :return: The wrapped function
    """

    def wrapped_function(*args, **kwargs):
        Store.verify_name(args[0].store)
        function(*args, **kwargs)

    return wrapped_function


def add(args: argparse.Namespace):
    """
    Add a value to a store. If the store doesn't exists, create it.
    :param args: The cli args
    """
    message = f"Set {args.field} value: "
    if args.secret:
        value = getpass.getpass(message)
    else:
        value = input(message)

    try:
        store = secret_store_manager.load(args.store)
        store.fields[args.field] = value
    except FileNotFoundError:
        store = Store(args.store, {args.field: value})
    secret_store_manager.save(store)


@_verify_store_name
@_gracefully_exist_if_not_found
def get(args: argparse.Namespace):
    """
    Retrieve a store or specific store field
    :param args: The cli args
    """
    store = secret_store_manager.load(args.store)
    if args.field is None:
        if args.json:
            print(json.dumps(store.fields))
        else:
            for field, value in store.fields.items():
                print(f"{field}: {value}")
    else:
        if args.json:
            print(json.dumps({args.field: store.fields[args.field]}))
        else:
            print(store.fields[args.field])


@_verify_store_name
@_gracefully_exist_if_not_found
def delete(args: argparse.Namespace):
    """
    Delete a store or a field from a store
    :param args: The cli args
    """
    if args.field is not None:
        store = secret_store_manager.load(args.store)
        if args.field in store.fields:
            del store.fields[args.field]
            if len(store.fields) == 0:
                secret_store_manager.delete(store.name)
            else:
                secret_store_manager.save(store)
        return

    if input(f"Are you sure to delete {args.store} store? (y/N): ").lower() in ["y", "yes"]:
        secret_store_manager.delete(args.store)
        print(f"{args.store} is deleted")
    else:
        print("No yes input. Cancelled")


def list_function(args: argparse.Namespace):
    for store in secret_store_manager.list():
        print(store)


def main():
    parser = argparse.ArgumentParser(description="Secret Store cli")
    parser.set_defaults(f=None)
    subparsers = parser.add_subparsers()

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("store", help="The name of the store")
    get_parser.add_argument("--field", help="Get a specific field")
    get_parser.add_argument("--json", action="store_true", help="Format the output as json")
    get_parser.set_defaults(f=get)

    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("store", help="The name of the store")
    add_parser.add_argument("field", help="Set a specific field")
    add_parser.add_argument("-s", "--secret", action="store_true", help="Do not display the value")
    add_parser.set_defaults(f=add)

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("store", help="The name of the store")
    delete_parser.add_argument("--field", help="Delete the field instead of the entire store")
    delete_parser.set_defaults(f=delete)

    list_parser = subparsers.add_parser("list")
    list_parser.set_defaults(f=list_function)

    args = parser.parse_args()

    if args.f is not None:
        args.f(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
