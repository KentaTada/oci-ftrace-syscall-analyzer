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
    let state_vals = utils::get_states_from_stdin();

    let cid = format!("{}", state_vals["id"].to_string());
    if cid == "" {
        panic!("cannot find container id");
    }

    let tracefs_path = utils::search_tracefs_path().expect(&format!("Failed to search tracefs"));
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
        .expect(&format!("cannot dump to {} ", &container_trace_file));
    fs::remove_dir(&trace_path).expect(&format!(
        "cannot remove ftrace instances dir {}",
        &trace_path
    ));
}
