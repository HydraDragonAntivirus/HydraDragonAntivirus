# wdk-mutex

An idiomatic Rust mutex type for Windows kernel driver development, supporting both `wdm` and `kmdf` drivers.

### Installation

To use this crate, simply:

```
cargo add wdk-mutex
```

In addition to defining either `WDM` or `KMDF` in your `Cargo.toml` as per the instructions given at [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs/), 
you **must** add the following to your `.cargo/config.toml`:

```toml
[build]
rustflags = [
  "-C", "target-feature=+crt-static",
  "--cfg", 'driver_model__driver_type="WDM"' # This line, make sure driver type matches your config, either WDM or KMDF
]
```

As per the above comment, ensure either `driver_model__driver_type="WDM"` for WDM, or `driver_model__driver_type="KMDF"`.

### Crate Info

**See the sections below for examples**. This crate assumes you already have a Rust Windows Driver Kit project
using the Microsoft [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) crate. You will
not be able to use this crate unless you are in a wdk development environment, setup steps outlined on
their repository.

This crate checks IRQL when acquiring and releasing the mutex, returning an error if IRQL is too high. See the crate documentation for details.

`wdk-mutex` is a work in progress to implement additional mutex types and functionality as required. Contributions, issues, and discussions are welcome. This crate is **NOT** affiliated with the WDK crates provided by Microsoft, but is designed to work with them and their ecosystem for Windows Rust 
Kernel Driver development.

As this crate integrates into the wdk ecosystem, Microsoft stipulate: This project is still in early stages of development and is not yet recommended for production use.

All tests are carried out at [wdk_mutex_tests](https://github.com/0xflux/wdk_mutex_tests), 
a separate repository which is built as a driver to test all functionality of the `wdk-mutex` crate. If you wish to run the tests
yourself, or contribute, please check that repository.

## Contributing

Contributions are welcome; if you do wish to contribute you will have to uncomment some items marked in the `Cargo.toml` to allow bindgen to produce the
necessary files on your local build (this is done automatically when you import this crate as either a `wdm` or `kmdf` project). When you are ready
to submit a PR, please ensure these are commented out as it will break for anybody using the opposite framework.

## Licence

This is licenced with an MIT Licence, conditions can be found in LICENCE in the crate GitHub repository.

## Features:

**Global mutex tracking:**

The `wdk-mutex` crate allows you to easily create, track, and use mutexes for a Windows Kernel Driver across all threads and 
callbacks. This improves developer ergonomics in creating, tracking, dropping etc mutexes throughout your drivers codebase. 

To use it, the `Grt` (Global Reference Tracker) module will allocate a safe reference tracker, allowing you to then register a `T` to be protected by a Mutex. This
registration takes a `&'static str` which is the key for the Mutex object. At runtime, you are able to safely retrieve the mutex and operate
on the inner T across threads and callbacks.

The `Grt` will also **prevent memory leaks** as it implements a `destroy()` function which you call only once, and all data tracked by the `Grt` will be deallocated, 
making life much easier tracking global static data in a driver.

**KMUTEX:** 

The `wdk-mutex` crate supports acquiring a KMUTEX. The type `Kmutex<T>` provides mutually exclusive access
to the inner type T allocated through this crate in the non-paged pool. All data required to initialise the 
KMutex is allocated in the non-paged pool and as such is safe to pass stack data into the type as it will not go out of scope.

Access to the `T` within the `KMutex` can be done through calling `lock`, similar to the Rust std Mutex.

As the `KMutex` is designed to be used in the Windows Kernel, with the Windows `wdk` crate, the lifetimes of 
the `KMutex` must be considered by the caller. See **examples** below for usage.

**FAST_MUTEX:** 

As well as a `KMUTEX`, `wdk-mutex` also supports the use of acquiring a [FAST_MUTEX](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess). Locking a FAST_MUTEX is faster than locking a `KMUTEX`.

# Examples

To see a real project using this, check my [Sanctum driver](https://github.com/0xflux/Sanctum). Alternatively, check the [tests repo](https://github.com/0xflux/wdk_mutex_tests) for this crate which tests features which will give you inspiration as to how the mutexes can be used. I would recommend utilising the `Grt` 
module for globally accessible mutexes.

## Locally scoped mutex:

```rust
{
    let mtx = KMutex::new(0u32).unwrap();
    let lock = mtx.lock().unwrap();

    // If T implements display, you do not need to dereference the lock to print.
    println!("The value is: {}", lock);
} // Mutex will become unlocked as it is managed via RAII 
```

## Global scope via wdk-mutex Grt:

To use mutexes across your driver at runtime with ease:

```rust
// Initialise the mutex on DriverEntry

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    if let Err(e) = Grt::init() {
        println!("Error creating Grt!: {:?}", e);
        return STATUS_UNSUCCESSFUL;
    }

    // ...
    my_function();
}


// Register a new Mutex in the `Grt` of value 0u32:

pub fn my_function() {
    Grt::register_fast_mutex("my_test_mutex", 0u32);
}

unsafe extern "C" fn my_thread_fn_pointer(_: *mut c_void) {
    let my_mutex = Grt::get_fast_mutex::<u32>("my_test_mutex");
    if let Err(e) = my_mutex {
        println!("Error in thread: {:?}", e);
        return;
    }

    let mut lock = my_mutex.unwrap().lock().unwrap();
    *lock += 1;
}


// Destroy the Grt to prevent memory leak on DriverExit

extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    unsafe {Grt::destroy()};
}
```

# Stability

This crate has been built and tested with **nightly-2024-12-21**. Stability outside of nightly versions
stipulated here are considered undefined.

The crate has been tested on a Windows 11 image as a driver. No testing of other Windows versions have 
been conducted.

# Planned updates

## Critical Sections:

An idiomatic implementation for entering and leaving a mutex critical section where no underlying 
T is protected.