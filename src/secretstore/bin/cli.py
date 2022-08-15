import argparse
import getpass
import json
from typing import Callable

from secretstore import SecretStoreManager, Store

secret_store_manager = SecretStoreManager()


def _gracefully_exist_if_not_found(function: Callable) -> Callable:
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


def _verify_store_name(function: Callable) -> Callable:
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

    if secret_store_manager.exists(args.store):
        store = secret_store_manager.load(args.store)
        store.fields[args.field] = value
    else:
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
    Delete a store
    :param args: The cli args
    """
    if input(f"Are you sure to delete {args.store} store? (y/N): ").lower() in ["y", "yes"]:
        secret_store_manager.delete(args.store)
        print(f"{args.store} is deleted")
    else:
        print("No yes input. Cancelled")


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
    delete_parser.set_defaults(f=delete)

    args = parser.parse_args()

    if args.f is not None:
        args.f(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
