/// integration tests for full binary
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn bin_version() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd.arg("-V").assert();
    assert.stdout(predicate::str::contains("0.3.2")).success();
}

#[test]
fn bin_convert_notext() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd.args(&["convert", "foo.dlt"]).assert();
    assert.failure();
}
