from typing import Final, Optional, NoReturn, Callable, Any, Union
from pathlib import Path
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timedelta
from pwd import getpwuid
from struct import pack
from socket import AF_INET, inet_ntop

from bcc import BPF

from log_tracer.structures.process_info import ProcessInfo
from log_tracer.structures.connection_info import ConnectionInfo
from log_tracer.structures.callback_type import CallbackType
from log_tracer.utils import get_boot_time, get_info_from_proc


_BPF_TEXT: Final[str] = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define ARGSIZE 200

BPF_HASH(tgid_to_socket, u32, struct sock *);

struct arg_t {
    u32 pid;
    char argv[ARGSIZE];
};

struct arg_done_data_t {
    u64 start_boottime;
    u64 start_time;
    u64 exec_time;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

struct exec_ret {
    u32 pid;
    int return_value;
};

struct ret_t {
    u32 pid;
    int exit_code;
};

struct exit_t {
    u64 start_boottime;
    u64 start_time;
    u64 exit_time;
    u32 pid;
    u32 ppid;
    u32 tid;
    u32 uid;
    int exit_code;
    u32 sig_info;
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 ppid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};


BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);

BPF_PERF_OUTPUT(arg_events);
BPF_PERF_OUTPUT(arg_done_events);
BPF_PERF_OUTPUT(exec_done_events);
BPF_PERF_OUTPUT(process_exit_events);

BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    // stash the sock ptr for lookup on return
    tgid_to_socket.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver) {
    struct task_struct *task = (struct task_struct*) bpf_get_current_task();

    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u32 pid = pid_tgid >> 32;
    u32 ppid = task->real_parent->tgid;
    u32 tid = pid_tgid;

    struct sock **skpp;
    skpp = tgid_to_socket.lookup(&tid);
    if (skpp == 0)
        return 0;

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        tgid_to_socket.delete(&tid);
        return 0;
    }

    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    if (ipver == 4) {
        struct ipv4_data_t data4 = {
            .pid = pid,
            .ppid = ppid,
            .ip = ipver
        };
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else {
        struct ipv6_data_t data6 = {
            .pid = pid,
            .ppid = ppid,
            .ip = ipver,
        };
        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    tgid_to_socket.delete(&tid);

    return 0;
}


int trace_connect_v4_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 4);
}


int trace_connect_v6_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 6);
}

int syscall__execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *__argv, const char __user *const __user *__envp) {
    u32 pid =  bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct*) bpf_get_current_task();

    struct arg_done_data_t arg_done_data = {
        .start_boottime = task->start_boottime,
        .start_time = task->start_time,
        .exec_time = bpf_ktime_get_ns(),
        .pid = pid,
        .ppid = task->real_parent->tgid,
        .uid = bpf_get_current_uid_gid() & 0xffffffff
    };
    bpf_get_current_comm(&arg_done_data.comm, sizeof(arg_done_data.comm));
    bpf_probe_read_user(arg_done_data.filename, sizeof(arg_done_data.filename), (void *) filename);

    for (int i = 0; i < 20; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), (void *)&__argv[i]); 

        if (argp) {
            struct arg_t arg_data = {
                .pid = pid
            };
            bpf_probe_read_user(arg_data.argv, sizeof(arg_data.argv), (void *) argp);

            arg_events.perf_submit(ctx, &arg_data, sizeof(struct arg_t));
        } else {
            arg_done_events.perf_submit(ctx, &arg_done_data, sizeof(struct arg_done_data_t));

            return 0;
        }
    }

    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx){
    struct exec_ret data = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .return_value = PT_REGS_RC(ctx)
    };

    exec_done_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    if (task->pid != task->tgid || 0) { return 0; }

    struct exit_t exit_data = {
        .start_boottime = task->start_boottime,
        .start_time = task->start_time,
        .exit_time = bpf_ktime_get_ns(),
        .pid = task->tgid,
        .tid = task->pid,
        .uid = bpf_get_current_uid_gid() & 0xffffffff,
        .ppid = task->real_parent->tgid,
        .exit_code = task->exit_code >> 8,
        .sig_info = task->exit_code & 0xFF,
    };
    bpf_get_current_comm(&exit_data.comm, sizeof(exit_data.comm));

    process_exit_events.perf_submit(args, &exit_data, sizeof(exit_data));

    return 0;
}
"""

ValueType = Union[ProcessInfo, ConnectionInfo]


class LogTracer:

    def __init__(self):
        self._bpf_instance: Optional[BPF] = None

        self._pid_to_argv: dict[int, list[str]] = defaultdict(list)
        self._pid_to_num_exec_calls: dict[int, int] = defaultdict(int)
        self.pid_to_process_info: dict[int, ProcessInfo] = {}

        self._exec_callbacks: list[Callable[[ProcessInfo], Any]] = []
        self._process_exit_callbacks: list[Callable[[ProcessInfo], Any]] = []
        self._connection_callbacks: list[Callable[[ConnectionInfo], Any]] = []
        self._global_callbacks: list[Callable[[ValueType, CallbackType], Any]] = []

        self._callback_type_to_callback_list: dict[CallbackType, list[Callable]] = {
            CallbackType.EXEC: self._exec_callbacks,
            CallbackType.PROCESS_EXIT: self._process_exit_callbacks,
            CallbackType.CONNECTION: self._connection_callbacks
        }

    def register_callback(
        self,
        callback_function: Callable[[Union[ProcessInfo, ConnectionInfo], ...], Any],
        callback_type: Optional[CallbackType] = None
    ) -> None:
        """
        Register a callback.

        :param callback_function: The function to be called.
        :param callback_type: The type of callback to register. If none is specified, the callback function is
            registered to a global list.
        :return: None
        """

        if callback_type is None:
            self._global_callbacks.append(callback_function)
        else:
            self._callback_type_to_callback_list[callback_type].append(callback_function)

    def unregister_callback(
        self,
        callback_function: Callable[[ValueType, ...], Any],
        callback_type: Optional[CallbackType] = None
    ) -> None:
        """

        :param callback_function:
        :param callback_type:
        :return:
        """

        if callback_type is None:
            self._global_callbacks.remove(callback_function)
        else:
            self._callback_type_to_callback_list[callback_type].remove(callback_function)

    def _call_callback(self, value: ValueType, callback_type: CallbackType, use_global: bool = False):
        """

        :param value:
        :param callback_type:
        :param use_global: Whether to call the functions in the global callback list.
        :return:
        """

        if use_global:
            for callback_function in self._global_callbacks:
                callback_function(value, callback_type)
        else:
            for callback_function in self._callback_type_to_callback_list[callback_type]:
                callback_function(value)

    def run(self) -> NoReturn:
        self._bpf_instance = BPF(text=_BPF_TEXT)

        self._bpf_instance['arg_events'].open_perf_buffer(self._handle_arg_events)
        self._bpf_instance['arg_done_events'].open_perf_buffer(self._handle_arg_done_events)
        self._bpf_instance['exec_done_events'].open_perf_buffer(self._handle_exec_done_events)
        self._bpf_instance['process_exit_events'].open_perf_buffer(self._handle_process_exit_events)
        self._bpf_instance['ipv4_events'].open_perf_buffer(self._handle_ipv4_events)

        execve_fnname = self._bpf_instance.get_syscall_fnname('execve')
        self._bpf_instance.attach_kprobe(event=execve_fnname, fn_name='syscall__execve')
        self._bpf_instance.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
        self._bpf_instance.attach_kprobe(event='tcp_v4_connect', fn_name='trace_connect_entry')
        self._bpf_instance.attach_kprobe(event='tcp_v6_connect', fn_name='trace_connect_entry')
        self._bpf_instance.attach_kretprobe(event='tcp_v4_connect', fn_name='trace_connect_v4_return')
        self._bpf_instance.attach_kretprobe(event='tcp_v6_connect', fn_name='trace_connect_v6_return')

        while True:
            self._bpf_instance.perf_buffer_poll()

    def _handle_arg_events(self, cpu, data, size) -> None:
        event = self._bpf_instance['arg_events'].event(data)
        self._pid_to_argv[event.pid].append(event.argv.decode())

    def _handle_arg_done_events(self, cpu, data, size) -> None:
        event = self._bpf_instance['arg_done_events'].event(data)

        executable: str = event.filename.decode()
        if executable in {'/proc/self/exe', f'/proc/{event.pid}/exe'}:
            with suppress(FileNotFoundError, ProcessLookupError):
                executable = str(Path(f'/proc/{event.pid}/exe').resolve())

        # TODO: It would be nice if I could retrieve this in the BPF code...
        working_directory: Optional[str] = None
        with suppress(Exception):
            working_directory = str(Path(f'/proc/{event.pid}/cwd').resolve())

        boot_time: datetime = get_boot_time()

        process_info = ProcessInfo(
            executable=executable,
            name=event.comm.decode(),
            pid=event.pid,
            ppid=event.ppid,
            user_id=event.uid,
            user_name=getpwuid(event.uid).pw_name,
            working_directory=working_directory,
            start=(boot_time + timedelta(microseconds=event.start_boottime / 1000)).astimezone(),
            exec_time=(boot_time + timedelta(microseconds=(event.start_boottime + (event.exec_time - event.start_time)) / 1000)).astimezone(),
        )

        parent_process_info: Optional[ProcessInfo] = self.pid_to_process_info.get(event.ppid)

        if not parent_process_info:
            with suppress(FileNotFoundError, ProcessLookupError):
                parent_process_info: ProcessInfo = get_info_from_proc(pid=event.ppid)

        if parent_process_info:
            self.pid_to_process_info[event.ppid] = parent_process_info
            process_info.parent = parent_process_info

        self.pid_to_process_info[event.pid] = process_info

    def _handle_exec_done_events(self, cpu, data, size) -> None:

        # The `exec` call may be unsuccessful, in which case the return value is not `0`. (As I understand the
        # documentation, `exec` doesn't even return if it is successful; `0` happens to be the default value for
        # the data type that stores the return value; the "done callback" always gets called, though).
        # The reason the call is unsuccessful is typically that no file can be loaded from the path specified in the
        # argument. In which case, the `exec` will typically be reattempted with a new path based on the next directory
        # in the PATH variable. As the same pid is used, the corresponding "argv list" will be extended, with the
        # same arguments.

        event = self._bpf_instance['exec_done_events'].event(data)

        self._pid_to_num_exec_calls[event.pid] += 1

        if event.return_value != 0:
            return

        args: list[str] = self._pid_to_argv.pop(event.pid, None)
        if not args:
            return

        process_info: ProcessInfo = self.pid_to_process_info[event.pid]
        process_info.args = args[-int(len(args) / self._pid_to_num_exec_calls.pop(event.pid)):]

        self._call_callback(value=process_info, callback_type=CallbackType.EXEC, use_global=False)
        self._call_callback(value=process_info, callback_type=CallbackType.EXEC, use_global=True)

    def _handle_process_exit_events(self, cpu, data, size) -> None:
        event = self._bpf_instance['process_exit_events'].event(data)

        process_info: Optional[ProcessInfo] = self.pid_to_process_info.pop(event.pid, None)
        if not process_info:
            process_info = ProcessInfo(
                name=event.comm.decode(),
                pid=event.pid,
                ppid=event.ppid,
                user_name=getpwuid(event.uid).pw_name,
                user_id=event.uid
            )

        parent_process_info: Optional[ProcessInfo] = self.pid_to_process_info.get(event.ppid)
        if not parent_process_info:
            with suppress(FileNotFoundError, ProcessLookupError):
                parent_process_info: ProcessInfo = get_info_from_proc(pid=event.ppid)

        boot_time: datetime = get_boot_time()
        uptime_ns: int = event.exit_time - event.start_time

        process_info.exit_code = event.exit_code
        process_info.end = (boot_time + timedelta(microseconds=(event.start_boottime + uptime_ns) / 1000)).astimezone()
        process_info.uptime_ns = uptime_ns
        process_info.parent = parent_process_info

        self._call_callback(value=process_info, callback_type=CallbackType.PROCESS_EXIT, use_global=False)
        self._call_callback(value=process_info, callback_type=CallbackType.PROCESS_EXIT, use_global=True)

    def _handle_ipv4_events(self, cpu, data, size) -> None:
        event = self._bpf_instance['ipv4_events'].event(data)

        process_info = self.pid_to_process_info.get(event.pid)

        if not process_info:
            with suppress(FileNotFoundError, ProcessLookupError):
                process_info = get_info_from_proc(pid=event.pid)

        if not process_info:
            process_info = ProcessInfo(
                name=event.comm.decode(),
                pid=event.pid,
                ppid=event.ppid,
                user_name=getpwuid(event.uid).pw_name,
                user_id=event.uid
            )

        self.pid_to_process_info[event.pid] = process_info

        parent_process_info: Optional[ProcessInfo] = self.pid_to_process_info.get(event.ppid)

        if not parent_process_info:
            with suppress(FileNotFoundError, ProcessLookupError):
                parent_process_info: ProcessInfo = get_info_from_proc(pid=event.ppid)

        if parent_process_info:
            self.pid_to_process_info[event.ppid] = parent_process_info
            process_info.parent = parent_process_info

        connection_info = ConnectionInfo(
            source_address=inet_ntop(AF_INET, pack('I', event.saddr)),
            source_port=event.lport,
            destination_address=inet_ntop(AF_INET, pack('I', event.daddr)),
            destination_port=event.dport,
            process_info=process_info
        )

        self._call_callback(value=connection_info, callback_type=CallbackType.CONNECTION, use_global=False)
        self._call_callback(value=connection_info, callback_type=CallbackType.CONNECTION, use_global=True)
