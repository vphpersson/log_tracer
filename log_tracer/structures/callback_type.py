from enum import Enum, auto


class CallbackType(Enum):
    EXEC = auto()
    PROCESS_EXIT = auto()
    CONNECTION = auto()
