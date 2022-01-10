# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

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