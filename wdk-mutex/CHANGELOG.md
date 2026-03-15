# 1.3.2

Fixes [issue](https://github.com/0xflux/wdk-mutex/issues/13) where calling `to_owned` and `to_owned_box` drops the inner
`T`.

# 1.3.0

Bump version of wdk dependencies to latest edition.

# 1.2.0

PR removes the crate dependency on only WDM allowing the crate to be built with KMDF/UMDF targets. These are feature gated,
see updated README / crate docs for clarity on enabling.

# 1.1.0

Alter semver so this crate can be used with up-to-date versions of the wdk crates so long as they are 
compatible.

# 1.0.0

## Additions

Added an idiomatic implementation for FAST_MUTEX.

## Changes

The `Grt` now creates and fetches instances of both a `FastMutex` and a `KMutex` allowing both
mutex types to be stored and accessed globally.

Updated documentation for KMutex to include examples with `Grt` instead of the less ergonomic option of user managed global statics.

# 0.0.5

Version 0.0.5 introduces the Global Reference Tracker, and the `Grt` module which allows you to easily create, track, and use mutexes for a Windows Kernel Driver across all threads and 
callbacks. This improves developer ergonomics in creating, tracking, dropping etc mutexes throughout your drivers codebase.

# 0.0.4

Introduction of two new functions which allow the caller to get owned copy of the protected data (`T`):

- to_owned()
- to_owned_box()

