extern crate clap;
extern crate proc_mounts;
extern crate serde;
extern crate serde_json;

use clap::{App, Arg, SubCommand};
use std::process;

mod record;
mod report;
mod utils;

fn main() {
    let mut app = App::new("oci-ftrace-syscall-analyzer")
        .version("0.1")
        .subcommand(
            SubCommand::with_name("record")
                .about("Start ftrace syscall analyzer")
                .arg(
                    Arg::with_name("use-annots")
                        .long("--use-annots")
                        .help("If given, use annotations to control this tool"),
                )
                .arg(
                    Arg::with_name("buffer-size-kb")
                        .long("buffer-size-kb")
                        .takes_value(true)
                        .help("The ring buffer size for individual CPUs in KB"),
                ),
        )
        .subcommand(
            SubCommand::with_name("report")
                .about("Dump analyzer result")
                .arg(
                    Arg::with_name("seccomp-profile")
                        .long("seccomp-profile")
                        .help("Generate seccomp profile by the result of trace"),
                )
                .arg(
                    Arg::with_name("output")
                        .long("output")
                        .takes_value(true)
                        .default_value("./ftrace_syscalls_dump.log")
                        .help("output file path"),
                )
                .arg(
                    Arg::with_name("container-id")
                        .long("dump")
                        .takes_value(true)
                        .help("Dump specified container ID's logs while running"),
                ),
        );
    let cmd_args = app.clone().get_matches();

    if let Some(record_args) = cmd_args.subcommand_matches("record") {
        record::record(record_args);
        process::exit(0);
    }
    if let Some(dump_args) = cmd_args.subcommand_matches("report") {
        report::report(dump_args);
        process::exit(0);
    }

    app.print_help().unwrap();
    println!();
}
