class SSHKeyNotFound(Exception):
    def __init__(self):
        super().__init__("No supported ssh key was found")


class NoIdentities(Exception):
    def __init__(self) -> None:
        super().__init__("No identity found. Maybe try a 'secret-store identity sync'")


class NoIdentityForStoreFound(Exception):
    def __init__(self, store_name: str):
        super().__init__(f"No identity found for {store_name}")
