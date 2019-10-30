use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Clone, PartialEq)]
pub enum SeccompAction {
    ActKill,
    ActTrap,
    ActErrno,
    ActTrace,
    ActAllow,
    ActLog,
}

#[derive(Serialize, Deserialize, Debug)]
struct Syscall {
    names: Vec<String>,
    action: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Seccomp {
    defaultAction: String,
    syscalls: Vec<Syscall>,
}

impl Seccomp {
    pub fn new(
        default_action: SeccompAction,
        action: SeccompAction,
        syscalls: Vec<String>,
    ) -> Self {
        let convert_action = |action| -> String {
            match action {
                SeccompAction::ActKill => "SCMP_ACT_KILL".to_string(),
                SeccompAction::ActTrap => "SCMP_ACT_TRAP".to_string(),
                SeccompAction::ActErrno => "SCMP_ACT_ERRNO".to_string(),
                SeccompAction::ActTrace => "SCMP_ACT_TRACE".to_string(),
                SeccompAction::ActAllow => "SCMP_ACT_ALLOW".to_string(),
                SeccompAction::ActLog => "SCMP_ACT_LOG".to_string(),
            }
        };

        Seccomp {
            defaultAction: convert_action(default_action),
            syscalls: vec![Syscall {
                names: syscalls,
                action: convert_action(action),
            }],
        }
    }
}
