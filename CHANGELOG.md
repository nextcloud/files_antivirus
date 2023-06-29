# Changelog
All notable changes to this project will be documented in this file.

## [5.1.0] - 2023-05-17
## Added
* Add command to get background scanner status: `occ files_antvirus:status`
* Add command to trigger the background scanner: `occ files_antivirus:background-scan`
* Add command to manually scan a single file: `occ files_antivirus:scan`
* Add command to mark a file as scanner or unscanned: `occ files_antivirus:mark`

## [5.1.1] - 2023-06-15
## Fixed
* Fix compatibility with php 7.4

## [5.1.0] - 2023-05-17
## Added
* Support for Nextcloud 27

## [4.0.1] - 2022-12-06
## Fixed
* Correctly call parent constructor in background job by @come-nc in https://github.com/nextcloud/files_antivirus/pull/254

## [4.0.0] - 2022-11-23
## Fixed
* Fix lint checks on PHP 7.3 CI by @Pytal in https://github.com/nextcloud/files_antivirus/pull/226
* Fix type of scan timeout by @ChristophWurst in https://github.com/nextcloud/files_antivirus/pull/242

## Added
* Update version on master by @nickvergessen in https://github.com/nextcloud/files_antivirus/pull/211
* Update master target versions by @nickvergessen in https://github.com/nextcloud/files_antivirus/pull/210
* handle password protected files as 'scanned' in kaspersky by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/214
* Add tests for kaspersky scanner by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/215
* Optimize slow DB query by @SirTediousOfFoo in https://github.com/nextcloud/files_antivirus/pull/213
* use v3 of the kaspersky http api by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/216
* Support ICAP scanners by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/224
* Update version on master by @nickvergessen in https://github.com/nextcloud/files_antivirus/pull/229
* Update master target versions by @nickvergessen in https://github.com/nextcloud/files_antivirus/pull/228
* Update phpunit config by @nickvergessen in https://github.com/nextcloud/files_antivirus/pull/227
* psalm analysis and fixes by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/218
* move from app.php to IBootstart by @icewind1991 in https://github.com/nextcloud/files_antivirus/pull/233
* Handle encryption error by @CarlSchwan in https://github.com/nextcloud/files_antivirus/pull/236
* Shutdown scanner when handling encryption error by @CarlSchwan in https://github.com/nextcloud/files_antivirus/pull/240
* Update link to Kaspersky session timeout docs by @ChristophWurst in https://github.com/nextcloud/files_antivirus/pull/241

## [3.3.0] - 2022-05-14
## Fixed
- Nextcloud 24 support
- Use v3 of the Kaspersky API 
- Fix Kaspersky handing of un-scannable files

## [3.2.2] - 2021-09-14
## Fixed
- Background scan detecting file scanned after an infected file as also infected.
- Don't scan chunks on upload.

## [3.2.1] - 2021-03-04
## Added
- Fix Kaspersky scan handling of some cases

## [3.2.0] - 2021-03-04
## Added
- NC22 support

## Fixed
- Translations
- Kaspersky scan result handling

## [3.1.2] - 2021-01-28
### Fixed
- Handle unscanned Kaspersky scans
- Translations

## [3.1.1] - 2020-12-21
### Added
- Override setting to not run the background job

## [3.1.0] - 2020-12-10
### Added
- Nextcloud 21 support

### Fixed
- Translations
- Update scan time of infected files as well
- Reset infection status between scans
- Chunked scanning for Kaspersky

## [3.0.0] - 2020-09-01
### Added
- Kaspersky support

### Fixed
- Translations
- Readme

### Removed
- Nextcloud 17 support

## [2.4.1] - 2020-05-18
### Added
- Support for Nextcloud 20
- Regular background scan of old files

## [2.3.0] - 2020-04-03
### Added
- Support for Nextcloud 19

### Changed
- Translations updated

## [2.2.0] - 2019-10-03
### Added
- Support for Nextcloud 18

### Changed
- Translations updated

### Fixed
- Scanning of files without owner throws an error

## [2.1.1] - 2019-05-23
### Fixed
- Scanning of outdated files

## [2.1.0] - 2019-05-07
### Changed
- Restructured the DB queries for better performance

## [2.0.2] - 2019-03-19
### Changed
- Increase to scanning 100 files in cli background job

## [2.0.1] - 2019-02-21
### Fixed
- Compatibility with updated streamwrappers

### Changed
- Translations

## [2.0.0] - 2018-11-27
### Added
- Support for NC16
- Support for NC15 stream writes

### Changed
- Translations
- Release mechanism to krankerl

### Removed
- < NC15 support

### Fixed
- Also properly scan shared folder upload


## [1.4.1] - 2018-10-30
### Fixed
- Respect max scan filesize in chunked upload [#99](https://github.com/nextcloud/files_antivirus/pull/99)

## [1.4.0] - 2018-10-24
### Added
- Added CHANGELOG.md

### Changed
- Minimum supported Nextcloud is 13
- Moved over to database migrations [#95](https://github.com/nextcloud/files_antivirus/pull/95)

### Fixed
- Postgres databases should no longer throw errors [#86](https://github.com/nextcloud/files_antivirus/issues/86)
