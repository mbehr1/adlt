/// integration tests for full binary
use adlt::utils::remote_types::{self, BinType};
use assert_cmd::Command;
use portpicker::pick_unused_port;
use predicates::prelude::*;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tungstenite::Message;

#[test]
fn bin_version() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd.arg("-V").assert();
    assert
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")))
        .success();
}

#[test]
fn bin_convert_notext() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd.args(&["convert", "foo.dlt"]).assert();
    assert.failure();
}

#[test]
fn bin_convert_ex2() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex002.dlt");
    // convert command only -> just show lifecycles
    let assert = cmd
        .args(&["convert", &test_file.to_string_lossy()])
        .assert();
    assert
        .stdout(predicate::str::contains("have 4 lifecycles"))
        .success();
}

#[test]
fn bin_convert_ex2_lc_filter() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex002.dlt");
    // convert filter for a lifecycle
    let assert = cmd
        .args(&["convert", "-l", "3", "-a", &test_file.to_string_lossy()])
        .assert();
    assert
        .stdout(predicate::str::contains(
            "15:16.560007          0 001 E002 A001 C001 log info N 0 [[13] |]\n",
        ))
        .stderr(predicate::str::is_empty())
        .success();
}

#[test]
fn bin_convert_ex3() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex003.dlt");
    // convert cmd with -a ascii and end but not start index
    let assert = cmd
        .args(&["convert", "-a", "-e", "2", &test_file.to_string_lossy()])
        .assert();
    assert
        .stdout(predicate::str::contains(
            "   0 056 ECU- SER- ASC- log info V 1 [Only NL!]",
        ))
        .success();
}

#[test]
fn bin_convert_ex3_mixed() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex003.dlt");
    // convert cmd with -x hex output and begin and end index
    let assert = cmd
        .args(&[
            "convert",
            "-x",
            "-b",
            "2",
            "-e",
            "2",
            &test_file.to_string_lossy(),
        ])
        .assert();
    assert
        .stdout(predicate::str::contains(
            "47:13.142000          0 056 ECU- SER- ASC- log info V 1 [00 02 00 00 09 00 4f 6e 6c 79 20 4e 4c 21 00]",
        ))
        .success();
}

#[test]
fn bin_convert_ex3_headers() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex003.dlt");
    // convert cmd with -x hex output and begin and end index
    let assert = cmd
        .args(&[
            "convert",
            "-s",
            "-b",
            "2",
            "-e",
            "2",
            &test_file.to_string_lossy(),
        ])
        .assert();
    assert
        .stdout(predicate::str::contains(
            "47:13.142000          0 056 ECU- SER- ASC- log info V 1\n",
        ))
        .success();
}

#[test]
fn bin_convert_can() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("can_example1.asc");
    // convert command only -> just show lifecycles
    let assert = cmd
        .args(&["convert", &test_file.to_string_lossy()])
        .assert();
    assert
        .stdout(predicate::str::contains(
            "have 1 lifecycles:\nLC#  1: CAN1 ",
        )) // we omit the times due to local format
        .stdout(predicate::str::contains(":55:38 #     101 \n"))
        .success();
}

#[cfg(not(target_os = "windows"))]
#[test]
fn bin_remote_invalidport() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd.args(&["remote", "-v", "-p", "1"]).assert();
    println!("{:?}", assert.get_output());
    assert.failure();
}

#[test]
fn bin_remote_validport_listen() {
    let port: u16 = pick_unused_port().expect("no ports free");

    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let assert = cmd
        .args(&["remote", "-v", "-p", &format!("{}", port)])
        .timeout(std::time::Duration::from_secs(1))
        .assert()
        .stderr(predicate::str::contains(format!(
            "remote server listening on 127.0.0.1:{}",
            port
        )))
        .failure(); //.interrupted() <- fails on windows???
    println!("{:?}", assert.get_output());
}

#[test]
fn bin_remote_validport_connect() {
    let port: u16 = pick_unused_port().expect("no ports free");
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();

    // start the client that connects and sends close
    let t = std::thread::spawn(move || {
        println!("trying to connect to webclient at port {}", port);

        let mut ws;
        let start_time = Instant::now();
        loop {
            match tungstenite::client::connect(format!("wss://127.0.0.1:{}", port)) {
                Ok(p) => {
                    ws = p.0;
                    break;
                }
                Err(_e) => {
                    if start_time.elapsed() > Duration::from_secs(1) {
                        panic!("couldnt connect");
                    } else {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
        println!(
            "connected to webclient at port {} after {}ms",
            port,
            start_time.elapsed().as_millis()
        );

        ws.write_message(tungstenite::protocol::Message::Text("close".to_string()))
            .unwrap();
        let answer = ws.read_message().unwrap();
        assert!(answer.is_text());
        assert_eq!(
            answer.into_text().unwrap(),
            "err: close failed as no file open. open first!"
        );
        std::thread::sleep(Duration::from_millis(20));
    });

    let assert = cmd
        .args(&["remote", "-v", "-p", &format!("{}", port)])
        .timeout(std::time::Duration::from_secs(1))
        .assert()
        .stderr(predicate::str::contains(format!(
            "remote server listening on 127.0.0.1:{}",
            port
        )))
        .stderr(predicate::str::contains("err: close failed"))
        .failure(); // fails on windows: .interrupted();
    println!("{:?}", assert.get_output());
    t.join().unwrap();
}

use bincode::config;

const BINCODE_CONFIG: config::Configuration<
    config::LittleEndian,
    config::Fixint,
    config::WriteFixedArrayLength,
    config::NoLimit,
> = config::legacy(); // todo choose local endianess

#[test]
fn bin_remote_ex002_open() {
    let port: u16 = pick_unused_port().expect("no ports free");
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex002.dlt");

    // start the client that connects, sends open with file, checks for mandatory infos (no stream yet) and closes
    let t = std::thread::spawn(move || {
        let mut ws;
        let start_time = Instant::now();
        loop {
            match tungstenite::client::connect(format!("wss://127.0.0.1:{}", port)) {
                Ok(p) => {
                    ws = p.0;
                    break;
                }
                Err(_e) => {
                    if start_time.elapsed() > Duration::from_secs(1) {
                        panic!("couldnt connect");
                    } else {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
        ws.write_message(tungstenite::protocol::Message::Text(format!(
            r#"open {{"files":[{}]}}"#,
            serde_json::json!(test_file.to_str().unwrap()),
        )))
        .unwrap();
        let answer = ws.read_message().unwrap();
        assert!(answer.is_text());
        assert_eq!(
            answer.into_text().unwrap(),
            "ok: open {\"plugins_active\":[]}"
        );
        // check for the expected msgs:
        // FileInfo with up the proper nr_msgs
        // lifecycle info for 3 lifecycles (one is ctrl_request only)

        let mut got_file_info = false;
        let mut got_lcs = HashMap::new();
        let mut got_eac = HashMap::new();

        while let Ok(msg) = ws.read_message() {
            match msg {
                Message::Binary(d) => {
                    if let Ok((btype, _)) =
                        bincode::decode_from_slice::<remote_types::BinType, _>(&d, BINCODE_CONFIG)
                    {
                        match btype {
                            BinType::FileInfo(s) => {
                                println!("got binary msg FileInfo: {}", s.nr_msgs);
                                got_file_info = s.nr_msgs == 11696;
                            }
                            BinType::Lifecycles(lcs) => {
                                println!("got binary msg Lifecycles: {}", lcs.len());
                                for lc in lcs {
                                    got_lcs.insert(lc.id, ());
                                }
                            }
                            BinType::EacInfo(eacs) => {
                                println!("got binary msg EacInfo: {}", eacs.len());
                                for eac in eacs {
                                    println!(
                                        " eac ecu={:x} nr_msgs={}, #apids={}",
                                        eac.ecu,
                                        eac.nr_msgs,
                                        eac.apids.len()
                                    );
                                    got_eac.insert(eac.ecu, (eac.nr_msgs, eac.apids.len()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {} // ignore
            }
            if got_file_info
                && got_lcs.len() == 3
                && got_eac.values().map(|a| a.0).sum::<u32>() == 11696 // nr msgs
                && /* apids */ got_eac.values().map(|a| a.1).sum::<usize>() == 14
            {
                break;
            }
        }
        // send close
        ws.write_message(tungstenite::protocol::Message::Text("close".to_string()))
            .unwrap();
        let answer = ws.read_message().unwrap();
        assert!(answer.is_text(), "answer={:?}", answer);
        assert_eq!(answer.into_text().unwrap(), "ok: 'close'!");
        ws.close(None).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    });

    let assert = cmd
        .args(&["remote", "-v", "-p", &format!("{}", port)])
        .timeout(std::time::Duration::from_secs(3))
        .assert()
        .stderr(predicate::str::ends_with("websocket thread done\n"))
        .failure();
    println!("{:?}", assert.get_output());
    t.join().unwrap();
}

#[test]
fn bin_remote_ex002_stream() {
    let port: u16 = pick_unused_port().expect("no ports free");
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let mut test_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("tests");
    test_file.push("lc_ex002.dlt");

    // start the client that connects, sends open with file, checks for mandatory infos (no stream yet) and closes
    let t = std::thread::spawn(move || {
        let mut ws;
        let start_time = Instant::now();
        loop {
            match tungstenite::client::connect(format!("wss://127.0.0.1:{}", port)) {
                Ok(p) => {
                    ws = p.0;
                    break;
                }
                Err(_e) => {
                    if start_time.elapsed() > Duration::from_secs(1) {
                        panic!("couldnt connect");
                    } else {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
        ws.write_message(tungstenite::protocol::Message::Text(format!(
            r#"open {{"files":[{}]}}"#,
            serde_json::json!(test_file.to_str().unwrap()),
        )))
        .unwrap();
        let answer = ws.read_message().unwrap();
        assert!(answer.is_text());
        assert_eq!(
            answer.into_text().unwrap(),
            "ok: open {\"plugins_active\":[]}"
        );

        ws.write_message(tungstenite::protocol::Message::Text(format!(
            r#"stream {{"window":[1000,2000], "binary":true}}"#
        )))
        .unwrap();
        // check for the expected # of streamed msgs:

        let mut got_stream_ok = false;
        let mut got_msgs = 0usize;

        while let Ok(msg) = ws.read_message() {
            match msg {
                Message::Binary(d) => {
                    if let Ok((btype, _)) =
                        bincode::decode_from_slice::<remote_types::BinType, _>(&d, BINCODE_CONFIG)
                    {
                        match btype {
                            BinType::FileInfo(s) => {
                                println!("got binary msg FileInfo: {}", s.nr_msgs);
                            }
                            BinType::Lifecycles(lcs) => {
                                println!("got binary msg Lifecycles: {}", lcs.len());
                            }
                            BinType::EacInfo(eacs) => {
                                println!("got binary msg EacInfo: {}", eacs.len());
                            }
                            BinType::DltMsgs((_stream_id, msgs)) => {
                                println!("got binary msg DltMsgs: #{}", msgs.len());
                                got_msgs += msgs.len();
                            }
                            _ => {}
                        }
                    }
                }
                Message::Text(s) => {
                    println!("got text msg: {}", s);
                    if s.starts_with("ok: stream") {
                        // todo check stream id {"id":x,...} and compare with DltMsgs stream_id
                        got_stream_ok = true;
                    }
                }
                _ => {} // ignore
            }
            if got_stream_ok && got_msgs == 1000 {
                break;
            }
        }
        // send close
        ws.write_message(tungstenite::protocol::Message::Text("close".to_string()))
            .unwrap();
        let answer = ws.read_message().unwrap();
        assert!(answer.is_text(), "answer={:?}", answer);
        assert_eq!(answer.into_text().unwrap(), "ok: 'close'!");
        ws.close(None).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    });

    let assert = cmd
        .args(&["remote", "-v", "-p", &format!("{}", port)])
        .timeout(std::time::Duration::from_secs(3))
        .assert()
        .stderr(predicate::str::ends_with("websocket thread done\n"))
        .failure();
    println!("{:?}", assert.get_output());
    t.join().unwrap();
}
