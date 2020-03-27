#[macro_use]
mod err_converter;
#[macro_use]
mod syscalls;
mod oci_seccomp;

use self::err_converter::Error;
use self::oci_seccomp::{Seccomp, SeccompAction};
use super::utils;
use clap::ArgMatches;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process;

#[test]
fn test_convert_syscall_id() {
    let syscall_info = syscall_info!();
    assert_eq!(
        convert_syscall_id(&format!("aaaaaa:NR {} ", libc::SYS_accept), &syscall_info),
        Some("accept".to_string())
    );
}

fn convert_syscall_id(line: &str, syscall_info: &HashMap<i64, &str>) -> Option<String> {
    let prefix = "NR ";
    if let Some(pos) = line.rfind(prefix) {
        let s = line.get(pos + prefix.len()..).unwrap();
        let id: i64 = s.get(..s.find(' ').unwrap()).unwrap().parse().unwrap();
        return syscall_info.get(&id).map(|s| s.to_string());
    }
    None
}

#[test]
fn test_generate_profile() {
    let trace_file = "/tmp/oci-ftrace-syscall-analyzer-test.log";
    let mut file = File::create(&trace_file).unwrap();
    write!(
        file,
        "NR {} \nNR {} \nNR {} \nNR {} \n",
        libc::SYS_accept,
        libc::SYS_execve,
        libc::SYS_openat,
        libc::SYS_chroot
    )
    .unwrap();
    file.flush().unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&generate_profile(&trace_file)).unwrap(),
        serde_json::to_string_pretty(&Seccomp::new(
            SeccompAction::ActErrno,
            SeccompAction::ActAllow,
            vec![
                "chroot".to_string(),
                "execve".to_string(),
                "futex".to_string(),
                "openat".to_string()
            ]
        ))
        .unwrap()
    );
    fs::remove_file(&trace_file).unwrap();
}

fn generate_profile(trace_file: &str) -> Seccomp {
    let mut syscalls: Vec<String> = Vec::new();
    let mut invoked_from_container = false;
    let syscall_info = syscall_info!();
    for line in BufReader::new(File::open(&trace_file).unwrap()).lines() {
        if let Some(syscall) = convert_syscall_id(&line.unwrap(), &syscall_info) {
            if syscall == "execve" {
                invoked_from_container = true;
            }
            if invoked_from_container {
                syscalls.push(syscall);
            }
        };
    }
    syscalls.push("futex".to_string()); // Need to add futex due to runc
    syscalls.sort();
    syscalls.dedup();
    Seccomp::new(SeccompAction::ActErrno, SeccompAction::ActAllow, syscalls)
}

#[test]
fn test_remove_raw_syscall() {
    assert!(remove_raw_syscall("sys_enter:").is_none());
    assert!(remove_raw_syscall("sys_exit:").is_none());
    assert_eq!(
        remove_raw_syscall("sys_execve:"),
        Some("sys_execve:".to_string())
    );
}

fn remove_raw_syscall(line: &str) -> Option<String> {
    if line.find("sys_enter:").is_some() || line.find("sys_exit:").is_some() {
        return None;
    }
    Some(line.to_string())
}

#[test]
fn test_convert_error_info() {
    let error_info = error_info!();
    assert_eq!(
        convert_error_info(&format!("ret=0xfffffffffffffffe"), &error_info),
        "ret=ENOENT(no such file or directory)\n".to_string()
    );
}

fn convert_error_info(line: &str, error_info: &HashMap<&str, err_converter::Error>) -> String {
    if let Some(pos) = line.rfind("0x") {
        let ret = line.get(pos..).unwrap();
        if let Some(info) = error_info.get(ret) {
            return line.replace(ret, &format!("{}({})\n", &info.name, &info.desc));
        }
    }
    format!("{}\n", line.to_string())
}

pub fn report(report_args: &ArgMatches) {
    if 0 < report_args.occurrences_of("profile-output") && report_args.is_present("container-id") {
        println!("The argument '--livedump' cannot be used with '--seccomp-profile");
        process::exit(-1);
    }
    let mut cid;
    let state_vals = utils::get_states_from_stdin();
    cid = state_vals["id"].to_string();
    if cid == "" {
        panic!("cannot find container id");
    }
    if report_args.is_present("container-id") {
        cid = report_args.value_of("container-id").unwrap().to_string();
    }

    let tracefs_path =
        utils::search_tracefs_path().unwrap_or_else(|_| panic!("Failed to search tracefs"));
    let trace_path = format!(
        "{}/instances/{}",
        &tracefs_path,
        &cid.trim_matches('\\').trim_matches('"')
    );
    let container_trace_file = format!("{}/trace", &trace_path);

    if 0 < report_args.occurrences_of("profile-output") {
        let output_file_path = report_args.value_of("profile-output").unwrap().to_string();
        let mut output_file = BufWriter::new(File::create(output_file_path).unwrap());
        let profile = generate_profile(&container_trace_file);
        output_file
            .write_all(serde_json::to_string_pretty(&profile).unwrap().as_bytes())
            .unwrap();
        output_file
            .flush()
            .unwrap_or_else(|_| panic!("cannot dump to {} ", &container_trace_file));
    }

    let output_file_path = report_args.value_of("output").unwrap().to_string();
    let mut output_file = BufWriter::new(File::create(output_file_path).unwrap());
    let error_info = error_info!();
    for line in BufReader::new(File::open(&container_trace_file).unwrap()).lines() {
        if let Some(out) = remove_raw_syscall(&line.unwrap()) {
            output_file
                .write_all(convert_error_info(&out, &error_info).as_bytes())
                .unwrap();
        }
    }
    output_file
        .flush()
        .unwrap_or_else(|_| panic!("cannot dump to {} ", &container_trace_file));

    if !report_args.is_present("container-id") {
        if report_args.is_present("enable-ulog") {
            let ulog_dir_path = format!(
                "{}/rootfs/ulog",
                &state_vals["bundle"]
                    .to_string()
                    .trim_matches('\\')
                    .trim_matches('"')
            );
            let ulog_path = format!("{}/trace_marker", &ulog_dir_path);
            nix::mount::umount(Path::new(&ulog_path)).expect("bind mount is failed.");
            fs::remove_dir_all(&ulog_dir_path).unwrap_or_else(|_| {
                panic!(
                    "cannot remove ftrace marker for container {}",
                    &ulog_dir_path
                )
            });
        }
        fs::remove_dir(&trace_path)
            .unwrap_or_else(|_| panic!("cannot remove ftrace instances dir {}", &trace_path));
    }
}
