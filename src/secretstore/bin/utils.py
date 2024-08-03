def yes(message: str) -> bool:
    """
    Display the message for a yes no input

    :return: True if the response is yes, otherwise False
    """
    return input(f"{message} (y/n) ").lower() in ["yes", "y"]
