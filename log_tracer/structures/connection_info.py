from dataclasses import dataclass

from log_tracer.structures.process_info import ProcessInfo


@dataclass
class ConnectionInfo:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    process_info: ProcessInfo
