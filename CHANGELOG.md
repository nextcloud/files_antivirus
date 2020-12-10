# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
