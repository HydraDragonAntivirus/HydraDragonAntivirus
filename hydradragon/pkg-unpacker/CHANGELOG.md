# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2025-05-30

### Added

-   Some basic tests

### Fixed

-   Regression in path handling introduced in [`2.1.0`](#210---2025-03-08)

## [2.1.0] - 2025-03-08

### Added

-   Support for pkg 5.2.0 (using $ separators)
-   Support for pkg >= 5.0.0 and < 5.2.0

## [2.0.1] - 2025-03-08

### Added

-   Compression type and entrypoint logs
-   Supported tools in README

### Changed

-   Changed StoreType to reflect vercel/pkg names

### Fixed

-   Unpacker.readFile return when no compression is detected

## [2.0.0] - 2025-03-08

### Changed

-   TypeScript rewrite

## [1.0.2] - 2022-11-28

### Changed

-   Regex refactoring (#2)

## [1.0.1] - 2022-11-28

### Changed

-   Improve speed and use text content by default (#1)

## [1.0.0] - 2022-08-04

### Added

-   Initial release
