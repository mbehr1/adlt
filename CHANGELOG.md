# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.62.0 - 2025-07-12
#### Bug Fixes
- **(receive)** support skipping corrupt msgs - (f254442) - Matthias Behr
- **(receive)** use adlt test msg check in debug only - (b56379d) - Matthias Behr
- **(receive)** impl tcp receiver - (a8d4d71) - Matthias Behr
- **(receive)** add -e ecu_id parameter - (ca9184a) - Matthias Behr
#### Features
- **(receive)** add tcp forwarding - (53b404b) - Matthias Behr
- **(receive)** wip for receive via udp - (7cea0bb) - Matthias Behr
#### Miscellaneous Chores
- clippy fixes - (6681cd9) - Matthias Behr
- clippy fixes (automatically done) - (1571d36) - Matthias Behr
- add check for DLT vers 1 std header - (442170b) - Matthias Behr
- refactor parse_dlt_with_std_header - (b2c5be1) - Matthias Behr
#### Tests
- **(bin)** add two basic tests for receive and transmit - (a180e9f) - Matthias Behr
- **(receive)** incr coverage for recv_msg - (95ea0e4) - Matthias Behr
- **(receive)** basic create_send_socket tests - (df25411) - Matthias Behr
- **(receive)** add fragmented msg recv test - (4807154) - Matthias Behr
- **(receive)** extend with tcp receive - (9821cc3) - Matthias Behr
- **(receive)** add test to receive via udp - (c1bfee2) - Matthias Behr
- **(receive)** add first basic tests - (66c5b9c) - Matthias Behr
- **(transmit)** first basic test - (48aca12) - Matthias Behr
- parse_dlt_with_std_header - (3969e3c) - Matthias Behr

- - -

## v0.61.5 - 2025-06-01
#### Bug Fixes
- **(filetransfer)** speedup filetransfer state generation - (3b89d85) - Matthias Behr
- **(filetransfer)** support FLER and add error info - (e235324) - Matthias Behr
#### Refactoring
- **(filetransfer)** reduce duplicate code for arg_as_int/uint - (998e368) - Matthias Behr
#### Tests
- **(filetransfer)** add test for huge transfers - (0bc19b0) - Matthias Behr
- **(filetransfer)** add test for sorting of state treeItems - (e884bc2) - Matthias Behr
- **(filetransfer)** add unit tests for arg_as_int - (b02170d) - Matthias Behr

- - -

## v0.61.4 - 2025-05-18
#### Bug Fixes
- **(lc)** sort was not a total order - (766310f) - Matthias Behr
- **(someip)** improve text for decoding errors - (f1413f7) - Matthias Behr
#### Miscellaneous Chores
- **(deps)** update dependencies - (8b87443) - Matthias Behr
- fix clippy warnings - (5274686) - Matthias Behr
- provide thread names - (12b7421) - Matthias Behr

- - -

## v0.61.3 - 2025-03-29
#### Bug Fixes
- **(lc)** remove one println - (1cdcc9a) - Matthias Behr
#### Miscellaneous Chores
- **(deps)** update bincode to final 2.0.1 - (5c2c954) - Matthias Behr
- clippy warnings and serialize SCOD_ASCII - (5da3ae8) - Matthias Behr

- - -

## v0.61.2 - 2025-02-02
#### Bug Fixes
- **(control_msgs)** first payload byte was missing - (a0c9f1c) - Matthias Behr
#### Continuous Integration
- **(coverage)** use cargo-llvm-cov - (672f085) - Matthias Behr
- **(grcov)** remove usage of unsupported Zprofile flag - (e10f5d0) - Matthias Behr
#### Miscellaneous Chores
- **(clippy)** resolve clippy warnings - (88af287) - Matthias Behr
- **(test)** unit test for filter::from_quick_xml_reader - (ef5327a) - Matthias Behr
- **(tests)** unit test for unknown service - (8338d98) - Matthias Behr
- **(tests)** unit test for service ids - (09c69ab) - Matthias Behr
- **(tests)** incr coverage and add corner case support - (6d8c2c4) - Matthias Behr
- **(tests)** more coverage - (b13a649) - Matthias Behr
- **(updates)** update crates - (791e0c6) - Matthias Behr

- - -

## v0.61.1 - 2024-10-13
#### Bug Fixes
- **(lifecycle)** prefer RESUME than idlt lc detection - (3ce9801) - Matthias Behr
- msgs from merged lifecycles are buffered too long - (8d2b60e) - Matthias Behr
#### Continuous Integration
- build win32-arm64 - (8455648) - Matthias Behr

- - -

## v0.61.0 - 2024-10-08
#### Features
- **(remote)** one_pass streams - (e12b3e1) - Matthias Behr
#### Miscellaneous Chores
- clippy warnings - (41c6edc) - Matthias Behr

- - -

## v0.60.0 - 2024-07-24
#### Features
- use cache for list_archive_contents - (a8b3907) - Matthias Behr

- - -

## v0.59.0 - 2024-07-23
#### Bug Fixes
- **(unzip)** single archive files and reuse - (6835986) - Matthias Behr
- **(unzip)** support libarchive files with unknown size - (949c019) - Matthias Behr
- use const instead of libc for S_IFDIR - (b210976) - Matthias Behr
#### Continuous Integration
- use gha cache for vcpkg - (acb5c69) - Matthias Behr
- try different way to cache vcpkg for win - (e0575e6) - Matthias Behr
#### Features
- **(unzip)** enable libarchive for win x86_64 - (ac6f385) - Matthias Behr

- - -

## v0.58.1 - 2024-07-22
#### Bug Fixes
- **(archive)** support archive file names with glob pattern chars - (b6bb638) - Matthias Behr

- - -

## v0.58.0 - 2024-07-21
#### Continuous Integration
- strip release binary for macos arm as well - (0aa3c71) - Matthias Behr
- update runners to latest except for mac intel - (3ed6c5c) - Matthias Behr
#### Documentation
- **(readme)** add fuzz instructions - (8cb89d8) - Matthias Behr
#### Features
- **(unzip)** add support for remote - (6a6decc) - Matthias Behr
- **(unzip)** add feature unzip using zip/libarchive - (0761c55) - Matthias Behr
#### Miscellaneous Chores
- fix clippy warning - (bacf303) - Matthias Behr
#### Tests
- **(fuzz)** add first fuzz tests - (0c033a9) - Matthias Behr

- - -

## v0.57.1 - 2024-05-21
#### Bug Fixes
- **(someip)** impr log output for decoding errors - (3dd90e4) - Matthias Behr

- - -

## v0.57.0 - 2024-05-18
#### Bug Fixes
- abs_pos wrongly calculated - (d77c46b) - Matthias Behr
#### Features
- **(blf)** add blf file support to decode CAN msgs - (2143ba2) - Matthias Behr
#### Miscellaneous Chores
- add Seek to LowMarkBufReader - (bf04f2b) - Matthias Behr
#### Tests
- **(blf)** add tests for ErrorFrameExt and AppText - (5e8526d) - Matthias Behr

- - -

## v0.56.2 - 2024-05-07
#### Bug Fixes
- **(can)** support asc files with more than one whitespace - (420b87a) - Matthias Behr
- **(can)** support date with milliseconds - (a378fcf) - Matthias Behr

- - -

## v0.56.1 - 2024-05-01
#### Bug Fixes
- **(someip)** dont stop parsing on first service failure - (b290aa6) - Matthias Behr
#### Miscellaneous Chores
- removed outdated todos - (546fcb3) - Matthias Behr
- add MARKers to ease navigation - (726c3d4) - Matthias Behr
#### Tests
- add bench filter_multiple_criteria - (7574f30) - Matthias Behr
- fix flaky test bin_remote_ex002_stream - (5038345) - Matthias Behr

- - -

## v0.56.0 - 2024-04-07
#### Bug Fixes
- **(clippy)** false positive in rust 1.77 workaround - (1961f48) - Matthias Behr
- **(export)** typos and increase test coverage - (74f8835) - Matthias Behr
- **(lifecycle)** last updates were sometimes not send to clients - (997cf87) - Matthias Behr
- **(remote)** force sending of EAC, PluginState and FileInfo on parse end - (ab9c1ac) - Matthias Behr
- **(remote)** close blocking infinite - (f1aa15b) - Matthias Behr
- **(test)** flaky test fixed - (553492c) - Matthias Behr
#### Continuous Integration
- use CODECOV_TOKEN for coverage - (07c0926) - Matthias Behr
#### Features
- **(export)** add Export plugin - (1947137) - Matthias Behr
- **(remote)** add pause/resume command - (97e4fad) - Matthias Behr
- **(remote)** add option collect to open command - (ed8fc0f) - Matthias Behr
#### Refactoring
- **(plugins)** add sync_all and set_lifecycle_read_handle - (f387bf7) - Matthias Behr
- match_filters uses iter().any - (5067e61) - Matthias Behr

- - -

## v0.55.4 - 2024-03-22
#### Bug Fixes
- dont panic on logs with reception time around 1.1.1970 - (a5d78bc) - Matthias Behr

- - -

## v0.55.3 - 2024-03-18
#### Bug Fixes
- **(remote)** queries that have been chunked returned wrong len - (cc09f9e) - Matthias Behr

- - -

## v0.55.2 - 2024-03-18
#### Bug Fixes
- avoid accessing all_msgs out of bound - (78fbc19) - Matthias Behr
#### Continuous Integration
- remove win32-ia32 build - (857e186) - Matthias Behr

- - -

## v0.55.1 - 2024-03-17
#### Bug Fixes
- **(readme)** add .log info and mark as fix to trigger new release - (b2f51cf) - Matthias Behr
#### Continuous Integration
- change to dtolnay/rust-toolchain instead of unmaintained actions-rs/toolchain - (dd12464) - Matthias Behr
- update github actions - (5c12252) - Matthias Behr
- use actions-rs/toolchain instead of removed ructions - (d2bc2d0) - Matthias Behr

- - -

## v0.55.0 - 2024-03-17
#### Continuous Integration
- **(codecov)** update checkout and codecov-action to v4 - (2bc4d19) - Matthias Behr
- **(codecov)** actions-rs instead of ructions - (95ebb39) - Matthias Behr
#### Features
- add first support for generic (text) log files - (9ce74e1) - Matthias Behr
#### Performance Improvements
- **(remote)** chunked parallel search for queries - (bdbc20f) - Matthias Behr
- **(remote)** process stream filtering in parallel - (e5684f5) - Matthias Behr
- add bench for process_stream_new_msgs - (3d9ee2c) - Matthias Behr
- use par_iter for queries/non streams as well - (26e6224) - Matthias Behr
- use Cow for payload_as_text - (103d823) - Matthias Behr
#### Refactoring
- **(remote)** refactor StreamContext into lib functions - (7b0d31c) - Matthias Behr
#### Tests
- add sequence test for stream - (d70729f) - Matthias Behr

- - -

## v0.54.0 - 2024-02-26
#### Bug Fixes
- **(lifecycle)** consider slightly overlapping lcs - (50fb122) - Matthias Behr
- **(lifecycle)** handle non buffered lifecycles better - (c0f35a9) - Matthias Behr
- **(lifecycle)** lifecycles are buffered too long - (82f68f3) - Matthias Behr
#### Features
- **(convert)** add parameter for filters for ECU, APID or CTID. - (c0b8ce3) - Matthias Behr

- - -

## v0.53.0 - 2024-02-12
#### Features
- **(fibex)** show warnings from parsing - (3cbe61f) - Matthias Behr
#### Miscellaneous Chores
- update dependencies - (4126c57) - Matthias Behr
- update chrono dep - (5ec5a53) - Matthias Behr
- update slog-async and clap - (d68aea3) - Matthias Behr
- update regex crates - (b721de7) - Matthias Behr
#### Performance Improvements
- **(lifecycle)** optimize evmap update logic - (0dfccfb) - Matthias Behr
- use nohash for lifecycle hashmap - (f6d6b3d) - Matthias Behr
- optimize buf_as_hey_to_write - (c8b9e17) - Matthias Behr
- improve payload_as_text for non-verbose msgs - (5ec1781) - Matthias Behr
- add dlt_payload_nonverb bench - (766ab66) - Matthias Behr
- add payload_verb bench - (78a6373) - Matthias Behr

- - -

## v0.52.1 - 2024-02-04
#### Bug Fixes
- **(remote)** timestamps in ms as u64 - (e848b02) - Matthias Behr
#### Performance Improvements
- **(convert)** use bounded channel for filter_as_stream - (53953d5) - Matthias Behr
- **(convert)** use bound channels for buffer_sort_messages - (786d01d) - Matthias Behr
- **(convert)** use bounded channels for plugins processing - (eedc09f) - Matthias Behr
- **(convert)** use bounded channels - (1496701) - Matthias Behr
- **(remote)** use bounded channels - (3adf168) - Matthias Behr
- parse_lifecycles_buffered_from_stream use no_hash - (02ddbb0) - Matthias Behr
- use a binary_heap for buffer_sort_messages - (6d83d4d) - Matthias Behr
- filter_as_stream output fn - (e3834f3) - Matthias Behr
#### Refactoring
- add helper function to avoid duplicated code - (a52cf82) - Matthias Behr
- clippy fixes, return type introduced - (9d77785) - Matthias Behr
- fix bench baselines - (09f415e) - Matthias Behr

- - -

## v0.52.0 - 2024-01-22
#### Features
- **(remote)** allow to set listen addr - (cedaf84) - Matthias Behr

- - -

## v0.51.0 - 2024-01-21
#### Features
- **(remote)** add "fs" command to support full remote use-cases - (5bd987a) - Matthias Behr
#### Tests
- add tests for remote fs command - (15d1886) - Matthias Behr

- - -

## v0.50.0 - 2024-01-14
#### Features
- **(someip)** add methods to tree items for services and fields - (c408275) - Matthias Behr
- - -

## v0.49.0 - 2024-01-13
#### Features
- **(someip)** add reports for methods as well - (e0551df) - Matthias Behr
- **(someip)** use backslash for fire&forget requests - (40d6f37) - Matthias Behr
- - -

## v0.48.0 - 2024-01-02
#### Features
- **(remote)** add binary_search_by_msg_index - (6573a6b) - Matthias Behr
#### Miscellaneous Chores
- clippy fix - (6f7b266) - Matthias Behr
- - -

## v0.47.4 - 2023-12-17
#### Bug Fixes
- **(anonymize)** add reception time in ms to payload - (6e9523c) - Matthias Behr
- **(lifecycle)** handle idlts better - (293046a) - Matthias Behr
- - -

## v0.47.3 - 2023-12-16
#### Bug Fixes
- **(nonverbose)** Support msgs without CTID - (c41b1ee) - Matthias Behr
- - -

## v0.47.2 - 2023-12-10
#### Bug Fixes
- **(someip)** support reports for event parameter - (edfdce0) - Matthias Behr
- - -

## v0.47.1 - 2023-12-10
#### Bug Fixes
- **(someip)** js conv function captures wrong json - (f51952c) - Matthias Behr
- - -

## v0.47.0 - 2023-12-02
#### Bug Fixes
- improve logic for corrupt serial msgs - (5a349ab) - Matthias Behr
- add better log info for skipped bytes - (db7d50d) - Matthias Behr
#### Documentation
- update readme - (13c8c8b) - Matthias Behr
#### Features
- **(dls)** WIP/first basic support of reading serial dls - (9d346e4) - Matthias Behr
#### Miscellaneous Chores
- fmt and clippy fixes - (da41dff) - Matthias Behr
#### Tests
- add dls iterator test - (c3ab385) - Matthias Behr
- - -

## v0.46.0 - 2023-11-28
#### Bug Fixes
- **(muniic)** more warnings, some perf - (a7913b0) - Matthias Behr
- **(muniic)** add config to treeview - (298e20d) - Matthias Behr
#### Features
- **(serde)** add serializer for verbose payload - (5293dca) - Matthias Behr
#### Tests
- **(muniic)** add first content test - (1db7281) - Matthias Behr
- - -

## v0.45.1 - 2023-11-24
#### Bug Fixes
- **(muniic)** default hash, perf, treeItems - (ac05ed3) - Matthias Behr
- - -

## v0.45.0 - 2023-11-21
#### Features
- add new plugin muniic - (830d63b) - Matthias Behr
- - -

## v0.44.2 - 2023-11-18
#### Bug Fixes
- **(lifecycle)** detect overlapping lc start as sep lc - (cf9c85b) - Matthias Behr
#### Documentation
- update readme - (8650f8e) - Matthias Behr
#### Miscellaneous Chores
- prepare lc test for multiple files - (9dd0e8e) - Matthias Behr
#### Tests
- add debug_verify_lcs option - (579bc29) - Matthias Behr
- add script to determine nr of lcs per folder - (d85c1e6) - Matthias Behr
- - -

## v0.44.1 - 2023-11-12
#### Bug Fixes
- **(nonverbose)** add S_INTxy as S_SINTxy - (66ef06e) - Matthias Behr
- - -

## v0.44.0 - 2023-11-12
#### Features
- **(convert)** add plugins nonverbose, someip, rewrite, can - (60db247) - Matthias Behr
#### Miscellaneous Chores
- clippy fixes - (642be06) - Matthias Behr
- - -

## v0.43.0 - 2023-11-11
#### Features
- support regex for ecu, apid, ctid - (4953492) - Matthias Behr
- - -

## v0.42.1 - 2023-10-21
#### Bug Fixes
- resume lifecycles sometimes wrongly sorted - (01f2115) - Matthias Behr
#### Miscellaneous Chores
- cargo clippy fixes - (1ec4dbf) - Matthias Behr
- - -

## v0.42.0 - 2023-09-02
#### Features
- **(logcat)** support threadtime format - (f6febfe) - Matthias Behr
#### Tests
- logcat2dltmsgiterator timestamp test - (063095e) - Matthias Behr
- - -

## v0.41.0 - 2023-07-29
#### Bug Fixes
- **(logcat)** add apid descriptions - (bf05d80) - Matthias Behr
#### Features
- **(logcat)** add first support for logcat files - (26cc12c) - Matthias Behr
#### Miscellaneous Chores
- remove some log output - (bfdbb48) - Matthias Behr
- - -

## v0.40.1 - 2023-07-26
#### Bug Fixes
- dlt strings are non zero terminated by spec - (a17c59f) - Matthias Behr
- - -

## v0.40.0 - 2023-07-23
#### Features
- **(someip)** add franca_json support - (50599d6) - Matthias Behr
- - -

## v0.39.2 - 2023-06-30
#### Bug Fixes
- update a few crates - (c81ddb7) - Matthias Behr
#### Continuous Integration
- remove windows_gnu build - (1056739) - Matthias Behr
- - -

## v0.39.1 - 2023-06-30
#### Bug Fixes
- **(filetransfer)** support file names with full path - (d399dd9) - Matthias Behr
- - -

## v0.39.0 - 2023-05-21
#### Features
- **(remote)** add stream_search command - (dbc7ee0) - Matthias Behr
- - -

## v0.38.0 - 2023-05-18
#### Features
- **(remote)** send stream infos - (c10f05d) - Matthias Behr
- - -

## v0.37.0 - 2023-05-14
#### Features
- **(nonverbose)** hexdump only if non printable chars - (a089e2b) - Matthias Behr
- - -

## v0.36.2 - 2023-05-01
#### Bug Fixes
- **(ci)** use pat to trigger other workflow - (4a8a21d) - Matthias Behr
- - -

## v0.36.1 - 2023-05-01
#### Bug Fixes
- **(can)** avoid overlapping timestamps - (3e6e5a0) - Matthias Behr
#### Continuous Integration
- add trigger_release workflow - (1248442) - Matthias Behr
- - -

## v0.36.0 - 2023-04-26
#### Features
- can plugin: multiplexer support - (3cb607f) - Matthias Behr

- - -

## v0.35.0 - 2023-04-24
#### Features
- **(filetransfer)** show files sorted by name as well - (558d5fc) - Matthias Behr

- - -

## v0.34.0 - 2023-04-23
#### Features
- open time-wise overlapping files - (05e5590) - Matthias Behr
- open multiple can files - (547566f) - Matthias Behr
#### Performance Improvements
- add bench for Asc2DltMsgIterator - (d87ecb8) - Matthias Behr
#### Refactoring
- introduce get_dlt_infos_from_file - (298d79f) - Matthias Behr

- - -

## v0.33.2 - 2023-04-19
#### Bug Fixes
- CAN: support CANFD busmapping - (97b5875) - Matthias Behr

- - -

## v0.33.1 - 2023-04-18
#### Bug Fixes
- **(CAN)** respect endianess for signal instances - (4e934e2) - Matthias Behr

- - -

## v0.33.0 - 2023-04-16
#### Bug Fixes
- use json5 for conversionFns - (b4825ac) - Matthias Behr
#### Continuous Integration
- use actions-gh-release to upload artifacts - (ffe986e) - Matthias Behr
#### Features
- can plugin report with texttables/enums - (10bab0c) - Matthias Behr

- - -

## v0.32.2 - 2023-04-14
#### Bug Fixes
- use asomeip 0.4.1 with can decoding fixes - (5ed125a) - Matthias Behr
- support neg timestamps and hex canfd params - (7499f9c) - Matthias Behr
#### Miscellaneous Chores
- downgraded some logs from debug to trace - (4267841) - Matthias Behr

- - -

## v0.32.1 - 2023-04-11
#### Bug Fixes
- can plugin missing frames - (01a9698) - Matthias Behr
#### Continuous Integration
- use sekwah41 upload action - (fb3a863) - Matthias Behr
- replace actions-rs with ructions to support node16 - (1c42100) - Matthias Behr
- update gh actions to avoid node 12 - (6f90089) - Matthias Behr

- - -

## v0.32.0 - 2023-04-11
#### Build system
- pin bincode to 2.0.0-rc2 - (d872b16) - Matthias Behr
#### Features
- update asomeip to 0.4.0 - (43353f1) - Matthias Behr

- - -

## v0.31.0 - 2023-03-01
#### Bug Fixes
- **(remote)** send eac stats every 3s - (0a0a350) - Matthias Behr
- **(someip)** avoid panic on insane lengths - (7f5e4a2) - Matthias Behr
- **(sort)** sort order was sometimes wrong - (6d922c8) - Matthias Behr
- increase min buffer time for sort to 20s - (23e6bec) - Matthias Behr
#### Miscellaneous Chores
- remove debug output on filter match - (cdcc238) - Matthias Behr
#### Performance Improvements
- **(remote)** optimize if at stream end - (021ab71) - Matthias Behr
#### Tests
- **(convert)** add debug_verify_sort option - (261bbf8) - Matthias Behr

- - -

## v0.30.1 - 2023-02-11
#### Bug Fixes
- improve BusMapping logic - (a4311df) - Matthias Behr
#### Documentation
- **(convert)** add powershell warning - (e097115) - Matthias Behr
#### Miscellaneous Chores
- add ignore dir to tests - (75c8b15) - Matthias Behr
- update libs - (7490c34) - Matthias Behr
- fix ntest version to 0.9 - (b283d37) - Matthias Behr

- - -

## v0.30.0 - 2022-12-25
#### Features
- **(convert)** file transfer support - (63996f4) - Matthias Behr
#### Miscellaneous Chores
- **(clap)** update to v4.0 - (374019c) - Matthias Behr
- update asomeip version - (31e06e5) - Matthias Behr
- update packages - (c08ab37) - Matthias Behr
#### Tests
- **(convert)** add test for file_transfer - (a5368b0) - Matthias Behr
- **(remote)** add basic unit test - (7203051) - Matthias Behr

- - -

## v0.29.0 - 2022-12-18
#### Features
- **(convert)** add glob pattern support - (68df623) - Matthias Behr

- - -

## v0.28.4 - 2022-12-08
#### Bug Fixes
- bump version to v0.28.3 - (61da2b1) - Matthias Behr

- - -

## v0.28.3 - 2022-12-08
#### Bug Fixes
- **(remote)** ensure buffered lifecycles send - (2ae251e) - Matthias Behr
#### Miscellaneous Chores
- update chrono, regex, fancy-regex - (32f00e1) - Matthias Behr
- fix clippy warnings - (01636f5) - Matthias Behr

- - -

## v0.28.2 - 2022-09-07
#### Bug Fixes
- **(someip)** js event conversion fn for multiple parameter - (75d9186) - Matthias Behr

- - -

## v0.28.1 - 2022-08-17
#### Bug Fixes
- **(remote)** handle accpept timeout errors - (2463e7b) - Matthias Behr
#### Performance Improvements
- **(filter)** improve payload case insensitive - (b94abb7) - Matthias Behr
- add filter_bench as start point - (93f9784) - Matthias Behr
#### Tests
- make payload_ignore_case more tricky - (18f9c85) - Matthias Behr

- - -

## v0.28.0 - 2022-08-11
#### Features
- **(filter)** ignore_case_payload - (9978ca0) - Matthias Behr

- - -

## v0.27.1 - 2022-08-07
#### Bug Fixes
- mstp did assume non verbose ,impl loglevel - (8c6edc0) - Matthias Behr

- - -

## v0.27.0 - 2022-07-31
#### Features
- **(CAN)** support multiple fibex files - (10d6bf2) - Matthias Behr

- - -

## v0.26.0 - 2022-07-24
#### Bug Fixes
- **(someip)** show services by method, field, events - (4cb36e1) - Matthias Behr
#### Features
- **(someip)** add filter/report for events - (939dbd2) - Matthias Behr
- **(someip)** add filter for methods - (e21b270) - Matthias Behr
- **(someip)** add filter/report for fields - (b337bb2) - Matthias Behr
#### Miscellaneous Chores
- **(clippy)** fix clippy warnings - (122a256) - Matthias Behr

- - -

## v0.25.0 - 2022-07-21
#### Features
- **(can)** add CANFD error frame support - (e2ab41f) - Matthias Behr
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