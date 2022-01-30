# adlt README
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[![codecov](https://codecov.io/gh/mbehr1/adlt/branch/main/graph/badge.svg?[token=IXSFCJO277)](https://codecov.io/gh/mbehr1/adlt)
[![Build&Test](https://github.com/mbehr1/adlt/actions/workflows/rust.yml/badge.svg)](https://github.com/mbehr1/adlt/actions?query=workflow%3ARust)

This Rust crate provides a library and tools to help you to handle automotive DLT (diagnostic log and trace, see [GENIVI](https://at.projects.genivi.org/wiki/display/PROJ/Diagnostic+Log+and+Trace) or [AUTOSAR](https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-0/AUTOSAR_PRS_DiagnosticLogAndTraceProtocol.pdf)) files.

**Note:** This is a very early version and it's my first Rust project. It's not intended/ready yet for any kind of use. The interfaces will most likely change frequently!

## Features

- Open DLT files of any size.
- **Lifecycle detection** feature.
- **Sorting by timestamp** taking the lifecycles into account.
- **Filter**...

## Known Issues

Work in progress...

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
