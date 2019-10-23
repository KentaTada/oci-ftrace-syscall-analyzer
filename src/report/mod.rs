#[macro_use]
mod err_converter;

use self::err_converter::Error;
use super::utils;
use clap::ArgMatches;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

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
    let mut cid;
    if report_args.is_present("container-id") {
        cid = report_args.value_of("container-id").unwrap().to_string();
    } else {
        let state_vals = utils::get_states_from_stdin();
        cid = state_vals["id"].to_string();
        if cid == "" {
            panic!("cannot find container id");
        }
    }

    let tracefs_path =
        utils::search_tracefs_path().unwrap_or_else(|_| panic!("Failed to search tracefs"));
    let trace_path = format!(
        "{}/instances/{}",
        &tracefs_path,
        &cid.trim_matches('\\').trim_matches('"')
    );
    let container_trace_file = format!("{}/trace", &trace_path);

    let output_file_path = report_args.value_of("output").unwrap().to_string();
    let mut output_file = BufWriter::new(File::create(output_file_path).unwrap());
    let error_info = error_info!();
    for line in BufReader::new(File::open(&container_trace_file).unwrap()).lines() {
        let out = line.unwrap();
        output_file
            .write_all(convert_error_info(&out, &error_info).as_bytes())
            .unwrap();
    }
    output_file
        .flush()
        .unwrap_or_else(|_| panic!("cannot dump to {} ", &container_trace_file));

    if !report_args.is_present("container-id") {
        fs::remove_dir(&trace_path)
            .unwrap_or_else(|_| panic!("cannot remove ftrace instances dir {}", &trace_path));
    }
}
