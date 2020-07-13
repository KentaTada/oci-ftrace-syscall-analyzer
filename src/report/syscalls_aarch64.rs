#[macro_export]
macro_rules! syscall_aarch64_info {
    () => {{
        {
            let mut tmp = HashMap::new();
            tmp.insert(libc::SYS_io_setup, "io_setup");
            tmp.insert(libc::SYS_io_destroy, "io_destroy");
            tmp.insert(libc::SYS_io_submit, "io_submit");
            tmp.insert(libc::SYS_io_cancel, "io_cancel");
            tmp.insert(libc::SYS_io_getevents, "io_getevents");
            tmp.insert(libc::SYS_setxattr, "setxattr");
            tmp.insert(libc::SYS_lsetxattr, "lsetxattr");
            tmp.insert(libc::SYS_fsetxattr, "fsetxattr");
            tmp.insert(libc::SYS_getxattr, "getxattr");
            tmp.insert(libc::SYS_lgetxattr, "lgetxattr");
            tmp.insert(libc::SYS_fgetxattr, "fgetxattr");
            tmp.insert(libc::SYS_listxattr, "listxattr");
            tmp.insert(libc::SYS_llistxattr, "llistxattr");
            tmp.insert(libc::SYS_flistxattr, "flistxattr");
            tmp.insert(libc::SYS_removexattr, "removexattr");
            tmp.insert(libc::SYS_lremovexattr, "lremovexattr");
            tmp.insert(libc::SYS_fremovexattr, "fremovexattr");
            tmp.insert(libc::SYS_getcwd, "getcwd");
            tmp.insert(libc::SYS_lookup_dcookie, "lookup_dcookie");
            tmp.insert(libc::SYS_eventfd2, "eventfd2");
            tmp.insert(libc::SYS_epoll_create1, "epoll_create1");
            tmp.insert(libc::SYS_epoll_ctl, "epoll_ctl");
            tmp.insert(libc::SYS_epoll_pwait, "epoll_pwait");
            tmp.insert(libc::SYS_dup, "dup");
            tmp.insert(libc::SYS_dup3, "dup3");
            tmp.insert(libc::SYS_fcntl, "fcntl");
            tmp.insert(libc::SYS_inotify_init1, "inotify_init1");
            tmp.insert(libc::SYS_inotify_add_watch, "inotify_add_watch");
            tmp.insert(libc::SYS_inotify_rm_watch, "inotify_rm_watch");
            tmp.insert(libc::SYS_ioctl, "ioctl");
            tmp.insert(libc::SYS_ioprio_set, "ioprio_set");
            tmp.insert(libc::SYS_ioprio_get, "ioprio_get");
            tmp.insert(libc::SYS_flock, "flock");
            tmp.insert(libc::SYS_mknodat, "mknodat");
            tmp.insert(libc::SYS_mkdirat, "mkdirat");
            tmp.insert(libc::SYS_unlinkat, "unlinkat");
            tmp.insert(libc::SYS_symlinkat, "symlinkat");
            tmp.insert(libc::SYS_linkat, "linkat");
            tmp.insert(libc::SYS_renameat, "renameat");
            tmp.insert(libc::SYS_umount2, "umount2");
            tmp.insert(libc::SYS_mount, "mount");
            tmp.insert(libc::SYS_pivot_root, "pivot_root");
            tmp.insert(libc::SYS_nfsservctl, "nfsservctl");
            tmp.insert(libc::SYS_fallocate, "fallocate");
            tmp.insert(libc::SYS_faccessat, "faccessat");
            tmp.insert(libc::SYS_chdir, "chdir");
            tmp.insert(libc::SYS_fchdir, "fchdir");
            tmp.insert(libc::SYS_chroot, "chroot");
            tmp.insert(libc::SYS_fchmod, "fchmod");
            tmp.insert(libc::SYS_fchmodat, "fchmodat");
            tmp.insert(libc::SYS_fchownat, "fchownat");
            tmp.insert(libc::SYS_fchown, "fchown");
            tmp.insert(libc::SYS_openat, "openat");
            tmp.insert(libc::SYS_close, "close");
            tmp.insert(libc::SYS_vhangup, "vhangup");
            tmp.insert(libc::SYS_pipe2, "pipe2");
            tmp.insert(libc::SYS_quotactl, "quotactl");
            tmp.insert(libc::SYS_lseek, "lseek");
            tmp.insert(libc::SYS_read, "read");
            tmp.insert(libc::SYS_write, "write");
            tmp.insert(libc::SYS_readv, "readv");
            tmp.insert(libc::SYS_writev, "writev");
            tmp.insert(libc::SYS_pread64, "pread64");
            tmp.insert(libc::SYS_pwrite64, "pwrite64");
            tmp.insert(libc::SYS_preadv, "preadv");
            tmp.insert(libc::SYS_pwritev, "pwritev");
            tmp.insert(libc::SYS_pselect6, "pselect6");
            tmp.insert(libc::SYS_ppoll, "ppoll");
            tmp.insert(libc::SYS_signalfd4, "signalfd4");
            tmp.insert(libc::SYS_vmsplice, "vmsplice");
            tmp.insert(libc::SYS_splice, "splice");
            tmp.insert(libc::SYS_tee, "tee");
            tmp.insert(libc::SYS_readlinkat, "readlinkat");
            tmp.insert(libc::SYS_newfstatat, "newfstatat");
            tmp.insert(libc::SYS_fstat, "fstat");
            tmp.insert(libc::SYS_sync, "sync");
            tmp.insert(libc::SYS_fsync, "fsync");
            tmp.insert(libc::SYS_fdatasync, "fdatasync");
            tmp.insert(libc::SYS_sync_file_range, "sync_file_range");
            tmp.insert(libc::SYS_timerfd_create, "timerfd_create");
            tmp.insert(libc::SYS_timerfd_settime, "timerfd_settime");
            tmp.insert(libc::SYS_timerfd_gettime, "timerfd_gettime");
            tmp.insert(libc::SYS_utimensat, "utimensat");
            tmp.insert(libc::SYS_acct, "acct");
            tmp.insert(libc::SYS_capget, "capget");
            tmp.insert(libc::SYS_capset, "capset");
            tmp.insert(libc::SYS_personality, "personality");
            tmp.insert(libc::SYS_exit, "exit");
            tmp.insert(libc::SYS_exit_group, "exit_group");
            tmp.insert(libc::SYS_waitid, "waitid");
            tmp.insert(libc::SYS_set_tid_address, "set_tid_address");
            tmp.insert(libc::SYS_unshare, "unshare");
            tmp.insert(libc::SYS_futex, "futex");
            tmp.insert(libc::SYS_set_robust_list, "set_robust_list");
            tmp.insert(libc::SYS_get_robust_list, "get_robust_list");
            tmp.insert(libc::SYS_nanosleep, "nanosleep");
            tmp.insert(libc::SYS_getitimer, "getitimer");
            tmp.insert(libc::SYS_setitimer, "setitimer");
            tmp.insert(libc::SYS_kexec_load, "kexec_load");
            tmp.insert(libc::SYS_init_module, "init_module");
            tmp.insert(libc::SYS_delete_module, "delete_module");
            tmp.insert(libc::SYS_timer_create, "timer_create");
            tmp.insert(libc::SYS_timer_gettime, "timer_gettime");
            tmp.insert(libc::SYS_timer_getoverrun, "timer_getoverrun");
            tmp.insert(libc::SYS_timer_settime, "timer_settime");
            tmp.insert(libc::SYS_timer_delete, "timer_delete");
            tmp.insert(libc::SYS_clock_settime, "clock_settime");
            tmp.insert(libc::SYS_clock_gettime, "clock_gettime");
            tmp.insert(libc::SYS_clock_getres, "clock_getres");
            tmp.insert(libc::SYS_clock_nanosleep, "clock_nanosleep");
            tmp.insert(libc::SYS_syslog, "syslog");
            tmp.insert(libc::SYS_ptrace, "ptrace");
            tmp.insert(libc::SYS_sched_setparam, "sched_setparam");
            tmp.insert(libc::SYS_sched_setscheduler, "sched_setscheduler");
            tmp.insert(libc::SYS_sched_getscheduler, "sched_getscheduler");
            tmp.insert(libc::SYS_sched_getparam, "sched_getparam");
            tmp.insert(libc::SYS_sched_setaffinity, "sched_setaffinity");
            tmp.insert(libc::SYS_sched_getaffinity, "sched_getaffinity");
            tmp.insert(libc::SYS_sched_yield, "sched_yield");
            tmp.insert(libc::SYS_sched_get_priority_max, "sched_get_priority_max");
            tmp.insert(libc::SYS_sched_get_priority_min, "sched_get_priority_min");
            tmp.insert(libc::SYS_sched_rr_get_interval, "sched_rr_get_interval");
            tmp.insert(libc::SYS_restart_syscall, "restart_syscall");
            tmp.insert(libc::SYS_kill, "kill");
            tmp.insert(libc::SYS_tkill, "tkill");
            tmp.insert(libc::SYS_tgkill, "tgkill");
            tmp.insert(libc::SYS_sigaltstack, "sigaltstack");
            tmp.insert(libc::SYS_rt_sigsuspend, "rt_sigsuspend");
            tmp.insert(libc::SYS_rt_sigaction, "rt_sigaction");
            tmp.insert(libc::SYS_rt_sigprocmask, "rt_sigprocmask");
            tmp.insert(libc::SYS_rt_sigpending, "rt_sigpending");
            tmp.insert(libc::SYS_rt_sigtimedwait, "rt_sigtimedwait");
            tmp.insert(libc::SYS_rt_sigqueueinfo, "rt_sigqueueinfo");
            tmp.insert(libc::SYS_rt_sigreturn, "rt_sigreturn");
            tmp.insert(libc::SYS_setpriority, "setpriority");
            tmp.insert(libc::SYS_getpriority, "getpriority");
            tmp.insert(libc::SYS_reboot, "reboot");
            tmp.insert(libc::SYS_setregid, "setregid");
            tmp.insert(libc::SYS_setgid, "setgid");
            tmp.insert(libc::SYS_setreuid, "setreuid");
            tmp.insert(libc::SYS_setuid, "setuid");
            tmp.insert(libc::SYS_setresuid, "setresuid");
            tmp.insert(libc::SYS_getresuid, "getresuid");
            tmp.insert(libc::SYS_setresgid, "setresgid");
            tmp.insert(libc::SYS_getresgid, "getresgid");
            tmp.insert(libc::SYS_setfsuid, "setfsuid");
            tmp.insert(libc::SYS_setfsgid, "setfsgid");
            tmp.insert(libc::SYS_times, "times");
            tmp.insert(libc::SYS_setpgid, "setpgid");
            tmp.insert(libc::SYS_getpgid, "getpgid");
            tmp.insert(libc::SYS_getsid, "getsid");
            tmp.insert(libc::SYS_setsid, "setsid");
            tmp.insert(libc::SYS_getgroups, "getgroups");
            tmp.insert(libc::SYS_setgroups, "setgroups");
            tmp.insert(libc::SYS_uname, "uname");
            tmp.insert(libc::SYS_sethostname, "sethostname");
            tmp.insert(libc::SYS_setdomainname, "setdomainname");
            tmp.insert(libc::SYS_getrlimit, "getrlimit");
            tmp.insert(libc::SYS_setrlimit, "setrlimit");
            tmp.insert(libc::SYS_getrusage, "getrusage");
            tmp.insert(libc::SYS_umask, "umask");
            tmp.insert(libc::SYS_prctl, "prctl");
            tmp.insert(libc::SYS_getcpu, "getcpu");
            tmp.insert(libc::SYS_gettimeofday, "gettimeofday");
            tmp.insert(libc::SYS_settimeofday, "settimeofday");
            tmp.insert(libc::SYS_adjtimex, "adjtimex");
            tmp.insert(libc::SYS_getpid, "getpid");
            tmp.insert(libc::SYS_getppid, "getppid");
            tmp.insert(libc::SYS_getuid, "getuid");
            tmp.insert(libc::SYS_geteuid, "geteuid");
            tmp.insert(libc::SYS_getgid, "getgid");
            tmp.insert(libc::SYS_getegid, "getegid");
            tmp.insert(libc::SYS_gettid, "gettid");
            tmp.insert(libc::SYS_sysinfo, "sysinfo");
            tmp.insert(libc::SYS_mq_open, "mq_open");
            tmp.insert(libc::SYS_mq_unlink, "mq_unlink");
            tmp.insert(libc::SYS_mq_timedsend, "mq_timedsend");
            tmp.insert(libc::SYS_mq_timedreceive, "mq_timedreceive");
            tmp.insert(libc::SYS_mq_notify, "mq_notify");
            tmp.insert(libc::SYS_mq_getsetattr, "mq_getsetattr");
            tmp.insert(libc::SYS_msgctl, "msgctl");
            tmp.insert(libc::SYS_msgrcv, "msgrcv");
            tmp.insert(libc::SYS_msgsnd, "msgsnd");
            tmp.insert(libc::SYS_semget, "semget");
            tmp.insert(libc::SYS_semctl, "semctl");
            tmp.insert(libc::SYS_semtimedop, "semtimedop");
            tmp.insert(libc::SYS_semop, "semop");
            tmp.insert(libc::SYS_shmget, "shmget");
            tmp.insert(libc::SYS_shmctl, "shmctl");
            tmp.insert(libc::SYS_shmat, "shmat");
            tmp.insert(libc::SYS_shmdt, "shmdt");
            tmp.insert(libc::SYS_socket, "socket");
            tmp.insert(libc::SYS_socketpair, "socketpair");
            tmp.insert(libc::SYS_bind, "bind");
            tmp.insert(libc::SYS_listen, "listen");
            tmp.insert(libc::SYS_accept, "accept");
            tmp.insert(libc::SYS_connect, "connect");
            tmp.insert(libc::SYS_getsockname, "getsockname");
            tmp.insert(libc::SYS_getpeername, "getpeername");
            tmp.insert(libc::SYS_sendto, "sendto");
            tmp.insert(libc::SYS_recvfrom, "recvfrom");
            tmp.insert(libc::SYS_setsockopt, "setsockopt");
            tmp.insert(libc::SYS_getsockopt, "getsockopt");
            tmp.insert(libc::SYS_shutdown, "shutdown");
            tmp.insert(libc::SYS_sendmsg, "sendmsg");
            tmp.insert(libc::SYS_recvmsg, "recvmsg");
            tmp.insert(libc::SYS_readahead, "readahead");
            tmp.insert(libc::SYS_brk, "brk");
            tmp.insert(libc::SYS_munmap, "munmap");
            tmp.insert(libc::SYS_mremap, "mremap");
            tmp.insert(libc::SYS_add_key, "add_key");
            tmp.insert(libc::SYS_request_key, "request_key");
            tmp.insert(libc::SYS_keyctl, "keyctl");
            tmp.insert(libc::SYS_clone, "clone");
            tmp.insert(libc::SYS_execve, "execve");
            tmp.insert(libc::SYS_mmap, "mmap");
            tmp.insert(libc::SYS_swapon, "swapon");
            tmp.insert(libc::SYS_swapoff, "swapoff");
            tmp.insert(libc::SYS_mprotect, "mprotect");
            tmp.insert(libc::SYS_msync, "msync");
            tmp.insert(libc::SYS_mlock, "mlock");
            tmp.insert(libc::SYS_munlock, "munlock");
            tmp.insert(libc::SYS_mlockall, "mlockall");
            tmp.insert(libc::SYS_munlockall, "munlockall");
            tmp.insert(libc::SYS_mincore, "mincore");
            tmp.insert(libc::SYS_madvise, "madvise");
            tmp.insert(libc::SYS_remap_file_pages, "remap_file_pages");
            tmp.insert(libc::SYS_mbind, "mbind");
            tmp.insert(libc::SYS_get_mempolicy, "get_mempolicy");
            tmp.insert(libc::SYS_set_mempolicy, "set_mempolicy");
            tmp.insert(libc::SYS_migrate_pages, "migrate_pages");
            tmp.insert(libc::SYS_move_pages, "move_pages");
            tmp.insert(libc::SYS_rt_tgsigqueueinfo, "rt_tgsigqueueinfo");
            tmp.insert(libc::SYS_perf_event_open, "perf_event_open");
            tmp.insert(libc::SYS_accept4, "accept4");
            tmp.insert(libc::SYS_recvmmsg, "recvmmsg");
            tmp.insert(libc::SYS_wait4, "wait4");
            tmp.insert(libc::SYS_prlimit64, "prlimit64");
            tmp.insert(libc::SYS_fanotify_init, "fanotify_init");
            tmp.insert(libc::SYS_fanotify_mark, "fanotify_mark");
            tmp.insert(libc::SYS_name_to_handle_at, "name_to_handle_at");
            tmp.insert(libc::SYS_open_by_handle_at, "open_by_handle_at");
            tmp.insert(libc::SYS_clock_adjtime, "clock_adjtime");
            tmp.insert(libc::SYS_syncfs, "syncfs");
            tmp.insert(libc::SYS_setns, "setns");
            tmp.insert(libc::SYS_sendmmsg, "sendmmsg");
            tmp.insert(libc::SYS_process_vm_readv, "process_vm_readv");
            tmp.insert(libc::SYS_process_vm_writev, "process_vm_writev");
            tmp.insert(libc::SYS_kcmp, "kcmp");
            tmp.insert(libc::SYS_finit_module, "finit_module");
            tmp.insert(libc::SYS_sched_setattr, "sched_setattr");
            tmp.insert(libc::SYS_sched_getattr, "sched_getattr");
            tmp.insert(libc::SYS_renameat2, "renameat2");
            tmp.insert(libc::SYS_seccomp, "seccomp");
            tmp.insert(libc::SYS_getrandom, "getrandom");
            tmp.insert(libc::SYS_memfd_create, "memfd_create");
            tmp.insert(libc::SYS_bpf, "bpf");
            tmp.insert(libc::SYS_execveat, "execveat");
            tmp.insert(libc::SYS_userfaultfd, "userfaultfd");
            tmp.insert(libc::SYS_membarrier, "membarrier");
            tmp.insert(libc::SYS_mlock2, "mlock2");
            tmp.insert(libc::SYS_copy_file_range, "copy_file_range");
            tmp.insert(libc::SYS_preadv2, "preadv2");
            tmp.insert(libc::SYS_pwritev2, "pwritev2");
            tmp.insert(libc::SYS_pkey_mprotect, "pkey_mprotect");
            tmp.insert(libc::SYS_pkey_alloc, "pkey_alloc");
            tmp.insert(libc::SYS_pkey_free, "pkey_free");
            tmp.insert(libc::SYS_statx, "statx");
            tmp
        }
    }};
}