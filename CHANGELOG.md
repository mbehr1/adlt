# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.24.0 - 2022-07-19
#### Features
- **(can)** basic CANFD support - (0acd6ab) - Matthias Behr
- - -

## v0.23.0 - 2022-07-17
#### Features
- **(can)** add JS reportOptions.conversionFunction - (792ccd4) - Matthias Behr
- **(someip)** add JS reportOptions.conversionFunction - (fe8014a) - Matthias Behr
- - -

## v0.22.0 - 2022-07-17
#### Features
- **(can)** provide filterFrag for frames - (453add7) - Matthias Behr
- **(someip)** provide filterFrag for services - (cb2080d) - Matthias Behr
- - -

## v0.21.2 - 2022-07-04
#### Continuous Integration
- use cross v0.2.1 - (4948ff0) - Matthias Behr
- change to stable instead of nightly - (3b029a3) - Matthias Behr
- - -

## v0.21.1 - 2022-07-04
#### Bug Fixes
- **(can)** parse PM dates properly - (cd6228d) - Matthias Behr
#### Tests
- add FileTransferPlugin tests - (09d00df) - Matthias Behr
- add basic plugins_process_msgs test - (621885a) - Matthias Behr
- add plugin factory tests - (580698d) - Matthias Behr
- - -

## v0.21.0 - 2022-05-29
#### Features
- **(filetransfer)** add FileTransferPlugin for remote - (bc0aec1) - Matthias Behr
- - -

## v0.20.0 - 2022-05-22
#### Bug Fixes
- **(lifecycle)** detect lifecycles with timestamp 0 - (620ab17) - Matthias Behr
#### Features
- **(anon)** add anon option to convert - (d8398f5) - Matthias Behr
#### Tests
- add remote integration tests - (69d28ad) - Matthias Behr
- add convert integration tests - (0bee8b2) - Matthias Behr
- - -

## v0.19.0 - 2022-05-12
#### Features
- **(can)** provide more COMPU_METHODS based info - (5fa9d2d) - Matthias Behr
- - -

## v0.18.0 - 2022-05-08
#### Features
- **(suspend)** add detection of suspend/resume lifecycles - (a3c83b7) - Matthias Behr
- - -

## v0.17.0 - 2022-05-01
#### Features
- **(can_asc)** basic support of CAN files in asc format - (c34ad4e) - Matthias Behr
- **(can_plugin)** add CAN plugin to decode payload - (32461ef) - Matthias Behr
- - -

## v0.16.5 - 2022-04-26
#### Bug Fixes
- non verbose output format - (00cee5e) - Matthias Behr
- - -

## v0.16.4 - 2022-04-26
#### Bug Fixes
- lc end time and nr. msgs not correct - (cf7f0bc) - Matthias Behr
- - -

## v0.16.3 - 2022-04-22
#### Continuous Integration
- build linux-aarch64 - (76dd411) - Matthias Behr
- - -

## v0.16.2 - 2022-04-21
#### Documentation
- add install hint to pre-build binaries - (c84600c) - Matthias Behr
- - -

## v0.16.1 - 2022-04-21
#### Continuous Integration
- release remove complete folder - (9049722) - Matthias Behr
- use tag version on tag trigger - (93ce774) - Matthias Behr
- link statically for windows msvc - (e7834db) - Matthias Behr
- build macos-arm aarch64 as well - (c22477d) - Matthias Behr
- change to ubuntu-latest - (ceb24b0) - Matthias Behr
- automate release binaries generation - (05273ac) - Matthias Behr
#### Tests
- fix clippy warning - (84a912f) - Matthias Behr
- - -

## v0.16.0 - 2022-04-19
#### Bug Fixes
- **(nonverbose)** support MTIN/APID/CTID setting - (8649b1c) - Matthias Behr
- **(nonverbose)** support multiple fibex for same sw - (a12c934) - Matthias Behr
#### Features
- **(eac)** collect and send full EAC info - (661a052) - Matthias Behr
- **(eacstats)** first impl of EAC stats - (9df471f) - Matthias Behr
- **(rewrite)** basic PluginState support - (9e4286d) - Matthias Behr
- **(someip)** broadcast status for services - (3c1ff1c) - Matthias Behr
- plugin state broadcasted - (8d50c38) - Matthias Behr
#### Tests
- **(eac_stats)** improve coverage - (b7ddba2) - Matthias Behr
- basic tests for pluginstate - (f2fda12) - Matthias Behr
- - -

## v0.15.0 - 2022-04-16
#### Features
- **(nonverbose)** add NonVerbose plugin - (1031821) - Matthias Behr
- - -

## v0.14.0 - 2022-04-12
#### Features
- **(plugin)** add Rewrite plugin - (0bec6db) - Matthias Behr
- - -

## v0.13.0 - 2022-04-12
#### Features
- **(remote)** stream_change_window - (696c7b6) - Matthias Behr
- - -

## v0.12.1 - 2022-04-08
#### Bug Fixes
- **(filter)** payloadRegex use fancy-regex - (9315f48) - Matthias Behr
- fix clippy warning - (5a4b7c5) - Matthias Behr
#### Performance Improvements
- **(remote)** heuristic for all_msgs_len - (c131cde) - Matthias Behr
- - -

## v0.12.0 - 2022-04-03
#### Features
- **(filter)** control messages mstp, verb_mstp_mtin - (08c8561) - Matthias Behr
- **(remote)** stream_binary_search time_ms - (63df195) - Matthias Behr
- **(remote)** add sw_version to lc info - (6cf21f6) - Matthias Behr
- **(sw_version)** add SW vers to lifecycles - (c7bc643) - Matthias Behr
- service get_log_info - (d1f2281) - Matthias Behr
#### Miscellaneous Chores
- use asomeip 0.1.2 - (04813b1) - Matthias Behr
#### Performance Improvements
- minor inline optimizations and faster hasher - (e9a8823) - Matthias Behr
#### Refactoring
- remove Copy and use explicit clone - (014fa04) - Matthias Behr
- - -

## v0.11.0 - 2022-03-29
#### Bug Fixes
- updated asomeip, afibex deps - (4b278d7) - Matthias Behr
#### Documentation
- readme mention remote feature - (b5ba696) - Matthias Behr
#### Features
- **(someip)** segmented msgs support - (36ccbec) - Matthias Behr
#### Miscellaneous Chores
- **(version)** v0.10.0 - (9bd3919) - Matthias Behr
- change to rust 2021 edition - (c0e4db7) - Matthias Behr
#### Refactoring
- make some DltArg members pub - (5964d2c) - Matthias Behr
- - -

## v0.10.0 - 2022-03-28
#### Features
- **(plugins)** basic plugin infrastructure - (c827bc8) - Matthias Behr
#### Miscellaneous Chores
- use afibex and asomeip crate - (5eed378) - Matthias Behr
- - -

## v0.9.4 - 2022-03-19
#### Bug Fixes
- **(remote)** max_message_size and write_timeout - (285b8b8) - Matthias Behr
- - -

## v0.9.3 - 2022-03-18
#### Bug Fixes
- **(remote)** handle timedout as well - (ce4fe48) - Matthias Behr
- less verbose output - (a8bab23) - Matthias Behr
- - -

## v0.9.2 - 2022-03-18
#### Bug Fixes
- no panic if reception side closes earlier than sender - (f2b9e6f) - Matthias Behr
#### Tests
- fix clippy warnings - (158dd50) - Matthias Behr
- - -

## v0.9.1 - 2022-03-17
#### Bug Fixes
- **(parser)** dont panic on not yet supported types - (9ea6144) - Matthias Behr
- **(remote)** properly escape win path in tests - (8fb7239) - Matthias Behr
- **(remote)** print listening info on stdout as well - (3470ea7) - Matthias Behr
- - -

## v0.9.0 - 2022-03-15
#### Documentation
- add comment regarding persisted ids - (39d3520) - Matthias Behr
#### Features
- **(filter)** add lifecycles support - (96c5952) - Matthias Behr
- **(filter)** try to support ecmascript regex syntax - (11e407b) - Matthias Behr
- **(remote)** first poc/somewhat useable version - (51f8234) - Matthias Behr
#### Refactoring
- add as_buf and as_u32le for DltChar4 - (c79f91e) - Matthias Behr
- - -

## v0.8.0 - 2022-02-20
#### Documentation
- **(readme)** usage examples - (2bfb335) - Matthias Behr
#### Features
- **(convert)** filter file support - (17120fa) - Matthias Behr
#### Tests
- **(convert)** add filter_file test - (15ce43d) - Matthias Behr
- - -

## v0.7.1 - 2022-02-19
#### Bug Fixes
- **(convert)** flush output more often - (3d2d396) - Matthias Behr
#### Performance Improvements
- header_as_text_to_write - (04b60f5) - Matthias Behr
- - -

## v0.7.0 - 2022-02-13
#### Features
- **(convert)** add hex output - (96840a0) - Matthias Behr
#### Performance Improvements
- **(util)** optimize hex_to_bytes - (ac557af) - Matthias Behr
- **(util)** optimize buf_as_hex_to... - (d468022) - Matthias Behr
- add buf_as_hex and hex_to_bytes test - (99627c9) - Matthias Behr
#### Refactoring
- **(convert)** make the two loops more explicit - (c1bc40a) - Matthias Behr
- **(convert)** use DltMessageIterator - (8c7422f) - Matthias Behr
- **(remote)** use DltMessageIterator - (c1c9078) - Matthias Behr
#### Tests
- **(remote)** add more tests - (2212c7e) - Matthias Behr
- - -

## v0.6.0 - 2022-02-12
#### Features
- **(parse)** heuristic to detect corrupt messages - (4bf2a74) - Matthias Behr
#### Performance Improvements
- use regex replace_all instead of 3 replaces - (2f1d075) - Matthias Behr
- - -

## v0.5.0 - 2022-02-12
#### Features
- **(convert)** sort multiple input files - (6da3e6d) - Matthias Behr
#### Performance Improvements
- LowMarkBufReader read cache aligned - (0af34e2) - Matthias Behr
- measure read times for 1mio msgs - (3121948) - Matthias Behr
- - -

## v0.4.3 - 2022-02-05
#### Refactoring
- **(convert)** introduce LowMarkBufReader - (b13070a) - Matthias Behr
- parse_dlt_with_storage_header no reader - (d97d287) - Matthias Behr
- - -

## v0.4.2 - 2022-01-30
#### Performance Improvements
- use itoa crate for ints - (755ca69) - Matthias Behr
- use criterion and first optimization - (669e957) - Matthias Behr
#### Refactoring
- pass slog reference - (852bde1) - Matthias Behr
#### Tests
- **(convert)** add some (not) random data - (2039ce8) - Matthias Behr
- **(convert)** check output to file - (bd42a98) - Matthias Behr
- - -

## v0.4.1 - 2022-01-29
#### Bug Fixes
- **(dlt)** persist timestamp only if present - (abf5358) - Matthias Behr
- **(dlt)** replace write_vectored with write_all - (79b405c) - Matthias Behr
#### Documentation
- **(readme)** add some badges - (6cd3ef7) - Matthias Behr
#### Refactoring
- **(bin)** refactor to support tests - (686f699) - Matthias Behr
#### Tests
- **(convert)** test output and sort - (6fa97d4) - Matthias Behr
- **(convert)** more tests with test dlt file - (5535ef3) - Matthias Behr
- **(extheader)** mstp/mtin tests - (6d63d77) - Matthias Behr
- **(integration)** fix tests under windows - (eee30db) - Matthias Behr
- fix static version in integr. test - (10655a7) - Matthias Behr
- - -

## v0.4.0 - 2022-01-23
#### Bug Fixes
- **(dlt)** bool parsing, fail on len >1 - (9bff9ce) - Matthias Behr
- **(dlt)** handle SINT/UINT without payload - (fdf55a7) - Matthias Behr
#### Continuous Integration
- **(grcov)** add rust-cache - (78f7ea6) - Matthias Behr
- **(rust)** add rust-cache for rust build, clippy, tests as well - (c80b15c) - Matthias Behr
#### Features
- **(dlt)** parsing/decoding of FLOAT - (d309044) - Matthias Behr
- **(dlt)** proper string/rawd decoding - (ab27413) - Matthias Behr
#### Refactoring
- **(dlt)** use consts for arguments - (b36fcff) - Matthias Behr
#### Tests
- **(bin)** integration test for binary (just checking version) - (7eb8739) - Matthias Behr
- **(dlt)** parse_dlt_with_storage_header - (483a6aa) - Matthias Behr
- **(dlt)** more tests for uint/sint. Impl. 128bit types - (2b9c31b) - Matthias Behr
- **(dlt)** payload sint non vari - (8cf6a64) - Matthias Behr
- **(dlt)** more header_as_text_to_write tests - (c18f0d7) - Matthias Behr
- **(dlt)** DltMessage::to_write first test - (274fe9f) - Matthias Behr
- **(remote)** basic connect as websocket test - (062b1e8) - Matthias Behr
- **(remote)** test remote with invalid port - (d653b7b) - Matthias Behr
- **(util)** hex_to_bytes negative tests - (846358f) - Matthias Behr
- - -

## v0.3.2 - 2022-01-17
#### Bug Fixes
- **(convert)** remove debug output for uint args - (9c6862a) - Matthias Behr
#### Miscellaneous Chores
- **(util)** add hex_to_bytes - (42c5558) - Matthias Behr
#### Tests
- **(dlt)** more basic tests - (c3a9e04) - Matthias Behr
- **(dlt)** DltStandardHeader full - (ecf7c4c) - Matthias Behr
- **(dlt)** more DltStandardHeader tests - (c81bb71) - Matthias Behr
- **(dlt)** DltStandardHeader first tests - (6f5d129) - Matthias Behr
- **(dlt)** DltStorageHeader tests - (9322352) - Matthias Behr
- - -

## v0.3.1 - 2022-01-16
#### Miscellaneous Chores
- cargo fmt changes - (abbc972) - Matthias Behr
#### Tests
- **(lifecycle)** fix clippy warning - (ad320da) - Matthias Behr
- **(util)** buffer_sort_message_sorted_basic3 - (b432065) - Matthias Behr
- **(util)** one more test for buffer_sort_elements - (f8b7416) - Matthias Behr
- **(util)** first basic test for buffer_sort_messages - (78995ad) - Matthias Behr
- **(util)** test for utc_time_from_us - (afa71b1) - Matthias Behr
- - -

## v0.3.0 - 2022-01-16
#### Bug Fixes
- **(lifecycle)** merge with first LC (#4) - (8713549) - Matthias Behr
#### Miscellaneous Chores
- **(lifecycle)** remove interims lifecycle (#3) - (dc78d66) - Matthias Behr
- - -

## v0.2.0 - 2022-01-15
#### Bug Fixes
- **(lifecycle)** ignore timestamps > reception time - (fc90eb5) - Matthias Behr
#### Features
- **(lifecycle)** use last_reception_time for lc end - (06bec20) - Matthias Behr
- **(lifecycle)** implement proper merge handling - (b6f81ac) - Matthias Behr
#### Tests
- **(DltMessage)** add for_test_rcv_tms_ms helper - (68bfb19) - Matthias Behr
- **(lifecycle)** fix flaky test - (b8be0f8) - Matthias Behr
- add ntest to allow timeouts - (94d58e9) - Matthias Behr
- - -

## v0.1.4 - 2022-01-13
#### Bug Fixes
- panic with Utf8Error on invalid/corrupt ECU id (#2) - (6a9cd35) - Matthias Behr
#### Documentation
- **(readme)** add codecov appreciation - (8f94aff) - Matthias Behr
- - -

## v0.1.3 - 2022-01-10
#### Bug Fixes
- **(lib)** version returning package version - (c7fc05f) - Matthias Behr
- **(tests)** fix unit tests - (6efde42) - Matthias Behr
#### Continuous Integration
- **(commitlint)** add some debug info - (bf3bb7b) - Matthias Behr
- **(commitlint)** use cocogitto-action@v2 - (c42a8af) - Matthias Behr
- **(commitlint)** change git-user - (c0e729b) - Matthias Behr
- **(grcov)** upload to codecov - (95ca179) - Matthias Behr
- **(grcov)** add grcov workflow - (b506c11) - Matthias Behr
- **(rust)** trigger build only for push on main branch - (c5ed4ad) - Matthias Behr
- **(rust)** trigger on all but gh-pages branches - (5129444) - Matthias Behr
- add rust build/clippy/test workflow - (d21eca2) - Matthias Behr
- fix commitlint job - (98b756b) - Matthias Behr
- fix github workflow - (820e6e0) - Matthias Behr
- add commitlint for PRs - (94ff068) - Matthias Behr
- add funding github info - (a44e887) - Matthias Behr
#### Documentation
- **(README)** refer to CHANGELOG - (e55b65f) - Matthias Behr
- **(readme)** add codecov badge - (b0cb4a0) - Matthias Behr
- updated readme - (7a4be65) - Matthias Behr
#### Miscellaneous Chores
- **(version)** v0.1.2 - (0071467) - Matthias Behr
- **(version)** v0.1.1 - (b82124f) - Matthias Behr
- **(version)** v0.1.0 - (8c28494) - Matthias Behr
- cog bump support - (6e3b5d1) - Matthias Behr
#### Refactoring
- clippy... - (5274d75) - Matthias Behr
- clippy fixes - (2ff153f) - Matthias Behr
#### Tests
- **(dltchar4)** test coverage - (174441a) - Matthias Behr
- - -

## v0.1.2 - 2022-01-09
#### Bug Fixes
- **(tests)** fix unit tests - (fbbd869) - Matthias Behr
#### Continuous Integration
- **(commitlint)** add some debug info - (af09996) - Matthias Behr
- **(commitlint)** use cocogitto-action@v2 - (6cfbf0d) - Matthias Behr
- **(commitlint)** change git-user - (cd71936) - Matthias Behr
- **(rust)** trigger build only for push on main branch - (84bb3a0) - Matthias Behr
- **(rust)** trigger on all but gh-pages branches - (e7f3c5e) - Matthias Behr
- add rust build/clippy/test workflow - (cda874f) - Matthias Behr
- fix commitlint job - (74b8639) - Matthias Behr
- fix github workflow - (92320ac) - Matthias Behr
- add commitlint for PRs - (e9e8007) - Matthias Behr
- add funding github info - (30af2a8) - Matthias Behr
#### Documentation
- **(README)** refer to CHANGELOG - (31ee82a) - Matthias Behr
- - -

## v0.1.1 - 2022-01-09
#### Miscellaneous Chores
- cog bump support - (d3e093d) - Matthias Behr
- - -

## v0.1.0 - 2022-01-09
#### Bug Fixes
- lifecycle add 2nd check to avoid merge - (df6c374) - Matthias Behr
- dont stop on merge needed - (e7d6c89) - Matthias Behr
- remove warnings - (06fa1a5) - Matthias Behr
- convert:use BufWriter for output fileProvides a significant speedup (e.g. 1min15s -> 1-2s for a 500mb file) - (9bc6b82) - Matthias Behr
- add utils::utc_time_from_us - (6084ee1) - Matthias Behr
- removed warnings - (ea05c00) - Matthias Behr
- added vscode settings to gitignore - (7ef59fd) - Matthias Behr
- added readme - (33bc384) - Matthias Behr
- typos - (7cc6bea) - Matthias Behr
- added license identifier,... - (f430d26) - Matthias Behr
- add slog loggingrestructure binary files - (f9a873a) - Matthias Behr
- cmd line parsing - (1756553) - Matthias Behr
- interims mergeMerged different bits and pieces. - (c0048bf) - Matthias Behr
- Added parse_lifecycles_buffered_from_streamThis version avoids the need to handle interims version.Except if the parsing stops/starts with a buffered/non-validated lifecycle! - (f0e080c) - Behr Matthias
#### Continuous Integration
- add cocogitto to enforce conventional commits - (b6ead3d) - Matthias Behr
- v0.0.4 first mvpAscii and standard header print,Lifecycle filtering andoutput to filebasically working. - (319dc34) - Matthias Behr
- v0.3 - (7922038) - Matthias Behr
- v0.0.2interims version before adding first lifecycle functions. - (8aad4a8) - Matthias Behr
#### Documentation
- updated readme - (6762e28) - Matthias Behr
#### Features
- **(remote)** interims work/poc - (a1a97db) - Matthias Behr
- introduce remote - (d0bbb25) - Matthias Behr
- first output for convertAdd chronoFixed some fmt functions. - (d48ea21) - Matthias Behr
- add index to DltMessage - (6d42855) - Matthias Behr
#### Refactoring
- **(tests)** clippy warnings fixed for tests - (538596d) - Matthias Behr
- v0.0.7 fix clippy warnings - (54ba22f) - Matthias Behr
#### Style
- add output styles, removed debug output - (a5f6ddc) - Matthias Behr
#### Convert
- impl ascii output - (59b1d8e) - Matthias Behr
- remove hex and mixed - (e368ac1) - Matthias Behr
- first impl of output to file - (94d0b61) - Matthias Behr
- add filter_lc_ids - (34c7b45) - Matthias Behr
#### Dlt
- first partial parsing of payload - (eb6e140) - Matthias Behr
#### Lifecycle
- add get_sorted_lifecycles_as_vec - (c29a58d) - Matthias Behr
#### Utils
- buf_as_hex_to_write - (aeecc89) - Matthias Behr
- buffer_sort_messages impl - (01406f3) - Matthias Behr
- add buffer_sort_messages - (6f13984) - Matthias Behr
- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).