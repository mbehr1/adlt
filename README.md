# adlt README

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[![codecov](https://codecov.io/gh/mbehr1/adlt/branch/main/graph/badge.svg?[token=IXSFCJO277)](https://codecov.io/gh/mbehr1/adlt)
[![Build&Test](https://github.com/mbehr1/adlt/actions/workflows/rust.yml/badge.svg)](https://github.com/mbehr1/adlt/actions?query=workflow%3ARust)

This Rust crate provides a library and tools to help you to handle automotive DLT (diagnostic log and trace, see [GENIVI](https://at.projects.genivi.org/wiki/display/PROJ/Diagnostic+Log+and+Trace) or [AUTOSAR](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-0/AUTOSAR_PRS_DiagnosticLogAndTraceProtocol.pdf)) files.

**Note:** This is a very early version and it's my first Rust project. There might be lots of bugs or restrictions/partial implementations yet. The interfaces will most likely change frequently!

## Features

- Open DLT files of any size.
- Archives (zip or if compiled with feature "libarchive": 7z, rar, tar, tar.gz, tar.bz2, tar.xz) are extracted automatically to a temp dir.
- Multi-volume zip/7z support (simply use the .001 file, the others are opened automatically)
- Receive DLT files via UDP, UDP multicast or TCP
- Forward received DLT files via TCP to e.g. DLT-Viewer(s) with DLT-Viewer being able to reduce log-levels forwarded (e.g. for performance reasons)
- **Lifecycle detection** feature including detection (a bit heuristic) of "SUSPEND/RESUME" lifecycles for ECUs with suspend-to-ram implementations.
- **Sorting by timestamp** taking the lifecycles into account.
- **Filter**...

- **remote** server support: serve requests via wss. E.g. used with [DLT-Logs Visual Studio Code Extension](https://marketplace.visualstudio.com/items?itemName=mbehr1.dlt-logs).
- builtin **plugins** e.g. for
  - non-verbose message decoding
  - SOME/IP payload decoding,
  - **rewrite**ing of message timestamp or payload text,
  - **file transfer** extraction/detection.

## Supported file types

You can open

- DLT version 1 files
- DLT serial header files
- CAN "ASC" files with extension .asc
- Vector "binlog" files with extension .blf
- Android Logcat files with extension .txt
- Generic log files with extension .log and format per line like "[2024-03-09 23:01:31.627] [INF] [apid] text..." (INF is the log level).

Take care to not use `.txt`/`.asc`/`.blf`/`.log` extension for DLT file. Files with those extensions will be parsed as CAN/binlog/Android Logcat files.

## Usage examples

### command line tool

#### Show help for convert command:

```sh
adlt convert -h
```

#### Print ascii representation of a DLT file:

```sh
adlt convert -a <dlt_file>
```

#### Open all dlt files within a zip file:

```sh
adlt convert -a <zip_file>
```

#### Open a single dlt file within a zip file via a glob pattern:

```sh
adlt convert -a "zip_file/**/foo.dlt" # take care to use "" around the file name to avoid your shell to try to find the glob pattern
```

#### Show all lifecycles (ecu, time range, number of messages and SW verion) of a DLT file:

```
adlt convert <dlt_file>
...
have 3 lifecycles:
LC#  1: ECU1 2021/06/24 08:50:58.529663 - 08:53:51 #   26523 <sw version if contained as GET_SW_VERSION response>
LC#  2: ECU1 2021/06/24 08:54:29 RESUME - 08:55:08 #  181337 <sw version>
LC#  3: DLOG 2021/06/24 08:54:44.945600 - 08:54:44 #       1
```

#### Output/extract a specific lifecycle into file sorted by timestamps per lifecycle:

```sh
adlt convert <dlt_file> # to see the lifecycle ids. here e.g. LC#  1: ... and LC#  2: ...
adlt convert -l 1 2 -o <new_file> --sort <dlt_file> # export LC #1 and #2 sorted into new_file
```

#### Output only messages fitting to a filter into a new file:

```sh
# filter_file can be in dlt-convert format as a list of APID CTIDs. E.g. echo "API1 CTI1  API2 CTI2 " > filter_file
# or it can be in dlt-viewer dlf format (xml file with <?xml...><dltfilter><filter>... )
adlt convert -f <filter_file> -o <new_file> <dlt_file> # export all messages fitting to filter_file sorted into new_file
# lifecycle filters -l ... or sorting --sort can be applied as well!
```

#### Show lifecycles and embedded file transfers:

```sh
adlt convert --file_transfer=true --file_transfer_apid SYS --file_transfer_ctid FILE <dlt_file>
```

#### Export all core dumps to directory 'dumps' from a set of DLT files:

```sh
adlt convert --file_transfer='core*.gz' --file_transfer_path dumps --file_transfer_apid SYS --file_transfer_ctid FILE '**/*.dlt'
```

```
...
LC# 35: ECU1 2020/12/19 10:29:22.158128 - 10:29:39 #   15115
have 6 file transfers:
LC# 12: 'context.1584997735.controller.812.txt', 60kb
LC# 12: 'core.1584997735.controller.812.gz', 115kb , saved as: 'dumps/core.1584997735.controller.812.gz'
LC# 20: 'context.1585074417.controller.802.txt', 60kb
LC# 20: 'core.1585074417.controller.802.gz', 115kb , saved as: 'dumps/core.1585074417.controller.802.gz'
LC# 35: 'screenshot_20741013-092935_KOMBI.png', 7kb
LC# 35: 'screenshot_20741013-092935_HUD.png', 1kb
```

#### Receive via UDP, store to zip files with automatic file splitting and forward via TCP to e.g. DLT-Viewer:

As the DLT-Viewer has some issues receiving UDP msgs at a high frequency (sometimes it looses a few msgs) you can use
adlt to record DLT files and at the same time forward to DLT-Viewer via TCP.

```sh
# receive via multicast UDP on 224.0.0.1 on default port 3490 and forward to TCP on port 3490
# store all received logs in a zip file splitted to max 200mb
# Files will be named recv_dlt_xxx.zip
adlt receive 224.0.0.1 -u -t 3490 -c 200mb -o recv_dlt.zip
# stop receiving via ctrl-c signal
```

## Known Issues

Work in progress...

## How to install binaries

You can use the pre-build binaries from [adlt/releases](https://github.com/mbehr1/adlt/releases) or build your own ones:

## How to build

```
cargo build
cargo test
cargo build --release
```

### determine code coverage from unit tests

See CI generated code coverage results here:
[![codecov](https://codecov.io/gh/mbehr1/adlt/branch/main/graph/badge.svg?token=IXSFCJO277)](https://codecov.io/gh/mbehr1/adlt)

To install grcov support:

```
cargo install grcov
rustup install nightly
rustup default stable
rustup component add llvm-tools-preview
```

To generate coverage:

```
rm -rf ./target *.prof*
export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"
cargo +nightly build
cargo +nightly test
grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./coverage/
cd coverage
open ./index.html
```

### run benchmark tests

Benchmark tests are using criterion and cargo-criterion.
To install:

```
cargo install cargo-criterion
```

To run:

```
cargo criterion
or
cargo bench
```

The results will be printed on the console and an html report is created at

target/criterion/reports/index.html or
target/criterion/report/index.html.

To save a baseline use:

```
cargo bench --bench dlt_benches -- --save-baseline <name>
```

To compare against a saved baseline:

```
cargo bench --bench dlt_benches -- --baseline <saved_baseline_name>
```

### run fuzz tests

To list all available fuzz tests:

```
cargo +nightly fuzz list
```

You do need to have `cargo-fuzz` installed. To install use `cargo install cargo-fuzz`.

To run a fuzz test:

```
cargo +nightly fuzz <fuzz test name>
# e.g.
cargo +nightly fuzz dlt_v1_parse_std
```

The fuzz test never stop except if they find a problem. If you find any please create an issue for it or directly a PR with a fix.

### perform a release

```
cog bump --auto
```

### check commit messages

```
cog check -l
```

## Contributions

Any and all test, code or feedback contributions are welcome.
Open an [issue](https://github.com/mbehr1/adlt/issues) or create a pull request to make this library work better for everybody.

[![Donations](https://www.paypalobjects.com/en_US/DK/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2ZNMJP5P43QQN&source=url) Donations are welcome! (Contact me for commercial use or different [license](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)).

[GitHub ♥︎ Sponsors are welcome!](https://github.com/sponsors/mbehr1)

## Contributors

## Release Notes

see [CHANGELOG](./CHANGELOG.md)

## Third-party Content

This library leverages a lot of amazing 3rd party components distributed under MIT or MPL-2.0 or Apache-2.0 license. Thanks a lot to the authors!

See dependencies section in Cargo.toml for details.

Using cocogitto to enforce conventional commit messages.
Using codecov to host code-coverage results. Thx!
