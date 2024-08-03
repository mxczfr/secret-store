def yes(message: str) -> bool:
    response = input(f"{message} (y/n) ").lower()
    
    return response in ["yes", "y"]
