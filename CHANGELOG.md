# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
