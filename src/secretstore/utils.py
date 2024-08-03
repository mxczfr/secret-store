from abc import ABCMeta
from typing import Any


class Singleton(ABCMeta):
    _instances: dict[object, Any] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
