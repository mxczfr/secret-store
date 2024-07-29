class SSHKeyNotFound(Exception):
    def __init__(self):
        super().__init__("No ssh key was found")
