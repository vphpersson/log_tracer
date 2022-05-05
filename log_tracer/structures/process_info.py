from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from shlex import join as shlex_join


@dataclass
class ProcessInfo:
    name: str
    # pgid: ...
    pid: int
    ppid: int
    # entity_id: ...
    user_name: str
    user_id: int
    args: Optional[list[str]] = None
    executable: Optional[str] = None
    exec_time: Optional[datetime] = None
    end: Optional[datetime] = None
    exit_code: Optional[int] = None
    start: Optional[datetime] = None
    uptime_ns: Optional[int] = None
    working_directory: Optional[str] = None
    parent: Optional[ProcessInfo] = None

    @property
    def arg_count(self) -> int:
        return len(self.args)

    @property
    def command_line(self):
        return shlex_join(self.args)
