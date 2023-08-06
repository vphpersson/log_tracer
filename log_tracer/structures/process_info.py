from dataclasses import dataclass
from typing import Self
from datetime import datetime
from shlex import join as shlex_join


@dataclass
class ProcessInfo:
    name: str
    pid: int
    user_name: str
    user_id: int
    args: list[str] | None = None
    executable: str | None = None
    exec_time: datetime | None = None
    end: datetime | None = None
    exit_code: int | None = None
    ppid: int | None = None
    start: datetime | None = None
    uptime_ns: int | None = None
    working_directory: str | None = None
    parent: Self | None = None

    @property
    def arg_count(self) -> int:
        return len(self.args)

    @property
    def command_line(self):
        return shlex_join(self.args)
