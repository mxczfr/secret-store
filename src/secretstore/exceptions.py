class SSHKeyNotFound(Exception):
    def __init__(self):
        super().__init__("No supported ssh key was found")
