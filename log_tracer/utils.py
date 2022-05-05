from typing import Final
from re import compile as re_compile, MULTILINE as RE_MULTILINE, Pattern as RePattern
from os import sysconf as os_sysconf
from datetime import datetime, timedelta
from pathlib import Path
from pwd import getpwuid

from log_tracer.structures.process_info import ProcessInfo

_START_TIME_PATTERN: Final[RePattern] = re_compile(pattern=r'^.+\(.+\) (.+)$')
_UID_PATTERN: Final[RePattern] = re_compile(pattern=r'^Uid:\t+([^\t]+)\t.+$', flags=RE_MULTILINE)


def get_boot_time() -> datetime:
    return (datetime.now() - timedelta(seconds=float(Path('/proc/uptime').read_text().split()[0]))).astimezone()

# TODO: Don't `except` here.
# TODO: Consider order.


def get_info_from_proc(pid: int) -> ProcessInfo:

    pid_proc_path = Path(f'/proc/{pid}/')

    start_time = int(_START_TIME_PATTERN.search(string=(pid_proc_path / 'stat').read_text()).group(1).split()[19])

    ticks_per_second: int = os_sysconf('SC_CLK_TCK')

    uid = int(_UID_PATTERN.search(string=(pid_proc_path / 'status').read_text()).group(1))

    return ProcessInfo(
        args=[
            element.decode()
            for element in (pid_proc_path / 'cmdline').read_bytes().rstrip(b'\x00').split(b'\x00')
        ],
        executable=str((pid_proc_path / 'exe').readlink().resolve()),
        name=(pid_proc_path / 'comm').read_text().rstrip(),
        pid=pid,
        ppid=int((pid_proc_path / 'stat').read_text().split(' ')[3]),
        user_id=uid,
        user_name=getpwuid(uid).pw_name,
        working_directory=str((pid_proc_path / 'cwd').resolve()),
        start=get_boot_time() + timedelta(seconds=start_time / ticks_per_second)
    )
