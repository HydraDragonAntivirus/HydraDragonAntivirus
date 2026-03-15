//! GRT - Global Reference Tracker - a module to allow for global allocations of mutex
//! objects with an easy to use API. Easier than manually adding and tracking all static
//! allocations.

extern crate alloc;

use crate::{errors::GrtError, fast_mutex::FastMutex, kmutex::KMutex};
use alloc::{boxed::Box, collections::BTreeMap};
use core::{
    any::Any,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering::SeqCst},
};

// A static which points to an initialised box containing the `Grt`
static WDK_MTX_GRT_PTR: AtomicPtr<Grt> = AtomicPtr::new(null_mut());

/// The Global Reference Tracker (Grt) for `wdk-mutex` is a module designed to improve the development ergonomics
/// of manually managing memory in a driver required for tracking objects passed between threads.
///
/// The `Grt` abstraction makes it safe to register mutex objects and to retrieve them from callbacks and threads
/// at runtime in the driver, with idiomatic error handling. The `Grt` makes several pool allocations which are tracked
/// and managed safely via RAII, so if absolute minimal speed is required for accessing mutexes, you may wish to profile this
/// vs a manual implementation of tracking mutexes however you see fit.
///
/// The general way to use this, is to call [`Self::init`] during driver initialisation **once**, and on driver exit to call
/// [`Self::destroy`] **once**. In between calling `init` and `destroy`, you may add a new `T` (that will be protected by a
/// `wdk-mutex`) to the `Grt`, assigning a `&str` for the key of a `BTreeMap`, and the value being the `T`. **Note:** you do
/// not pass a `Mutex` into [`Self::register_kmutex`] or [`Self::register_fast_mutex`] etc; the function will automatically wrap that for you.
///
/// [`Self::get_kmutex`] / [`Self::get_fast_mutex`] etc will then allow you to retrieve the `Mutex` dynamically.
///
/// # Examples
///
/// ```
/// // Initialise the mutex
///
/// #[export_name = "DriverEntry"]
/// pub unsafe extern "system" fn driver_entry(
///     driver: &mut DRIVER_OBJECT,
///     registry_path: PCUNICODE_STRING,
/// ) -> NTSTATUS {
///     if let Err(e) = Grt::init() {
///         println!("Error creating Grt!: {:?}", e);
///         return STATUS_UNSUCCESSFUL;
///     }
///
///     // ...
///     my_function();
/// }
///
///
/// // Register a new Mutex in the `Grt` of value 0u32:
///
/// pub fn my_function() {
///     Grt::register_kmutex("my_test_mutex", 0u32);
/// }
///
/// unsafe extern "C" fn my_thread_fn_pointer(_: *mut c_void) {
///     let my_mutex = Grt::get_kmutex::<u32>("my_test_mutex");
///     if let Err(e) = my_mutex {
///         println!("Error in thread: {:?}", e);
///         return;
///     }
///
///     let mut lock = my_mutex.unwrap().lock().unwrap();
///     *lock += 1;
/// }
///
///
/// // Destroy the Grt to prevent memory leak on DriverExit
///
/// extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
///     unsafe {Grt::destroy()};
/// }
/// ```
pub struct Grt {
    global_kmutex: BTreeMap<&'static str, Box<dyn Any>>,
}

/// The type of mutexes which is passed in to the Grt to correctly initialise a new `mutex`.
pub enum MutexType {
    FastMutex,
    KMutex,
}

impl Grt {
    /// Initialise a new instance of the Global Reference Tracker for `wdk-mutex`.
    ///
    /// This should only be called once in your driver and will initialise the `Grt` to be globally available
    /// at any point you wish to utilise it to retrieve a mutex and its wrapped T.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - You have already initialised the `Grt`
    ///
    /// # Examples
    ///
    /// ```
    /// #[export_name = "DriverEntry"]
    /// pub unsafe extern "system" fn driver_entry(
    ///     driver: &mut DRIVER_OBJECT,
    ///     registry_path: PCUNICODE_STRING,
    /// ) -> NTSTATUS {
    ///     // A good place to initialise it is early during driver initialisation
    ///     if let Err(e) = Grt::init() {
    ///         println!("Error creating Grt! {:?}", e);
    ///         return STATUS_UNSUCCESSFUL;
    ///     }
    /// }
    /// ```
    pub fn init() -> Result<(), GrtError> {
        // Check we aren't double initialising
        if !WDK_MTX_GRT_PTR.load(SeqCst).is_null() {
            return Err(GrtError::GrtAlreadyExists);
        }

        //
        // Initialise a new Grt in a box, which will be converted to a raw pointer and stored in the static
        // AtomicPtr which is used for tracking the `Grt` structure.
        // On `Grt::destroy()` being called The raw pointer will then be converted from a ptr into a box,
        // allowing RAII to drop the memory properly when the destroy method is called.
        //

        let pool_ptr = Box::into_raw(Box::new(Grt {
            global_kmutex: BTreeMap::new(),
        }));

        WDK_MTX_GRT_PTR.store(pool_ptr, SeqCst);

        Ok(())
    }

    /// Register a new [`KMutex`] for the global reference tracker to control.
    ///
    /// The function takes a label as a static &str which is the key of a BTreeMap, and the type you wish
    /// to protect with the mutex as the data. If the key already exists, the function will indiscriminately insert
    /// a key and overwrite any existing data.
    ///
    /// If you wish to perform this function checking for an existing key before registering the mutex object,
    /// use [`Self::register_kmutex_checked`].
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - `Grt` has not been initialised, see [`Grt::init`]
    ///
    /// # Examples
    ///
    /// ```
    /// Grt::register_kmutex("my_test_mutex", 0u32);
    /// ```
    pub fn register_kmutex<T: Any>(label: &'static str, data: T) -> Result<(), GrtError> {
        // Check for a null pointer on the atomic
        let atomic_ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if atomic_ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        // Try initialise a new mutex
        let mtx = Box::new(KMutex::new(data).map_err(|e| GrtError::DriverMutexError(e))?);

        // SAFETY: The atomic pointer is checked at the start of the fn for a nullptr
        unsafe {
            (*atomic_ptr).global_kmutex.insert(label, mtx);
        }

        Ok(())
    }

    /// Register a new [`FastMutex`] for the global reference tracker to control.
    ///
    /// The function takes a label as a static &str which is the key of a BTreeMap, and the type you wish
    /// to protect with the mutex as the data. If the key already exists, the function will indiscriminately insert
    /// a key and overwrite any existing data.
    ///
    /// If you wish to perform this function checking for an existing key before registering the mutex object,
    /// use [`Self::register_fast_mutex_checked`].
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - `Grt` has not been initialised, see [`Grt::init`]
    ///
    /// # Examples
    ///
    /// ```
    /// Grt::register_fast_mutex("my_test_mutex", 0u32);
    /// ```
    pub fn register_fast_mutex<T: Any>(label: &'static str, data: T) -> Result<(), GrtError> {
        // Check for a null pointer on the atomic
        let atomic_ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if atomic_ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        // Try initialise a new mutex
        let mtx = Box::new(FastMutex::new(data).map_err(|e| GrtError::DriverMutexError(e))?);

        // SAFETY: The atomic pointer is checked at the start of the fn for a nullptr
        unsafe {
            (*atomic_ptr).global_kmutex.insert(label, mtx);
        }

        Ok(())
    }

    /// Register a new [`KMutex`] for the global reference tracker to control, throwing an error if the key already
    /// exists.
    ///
    /// This is a checked alternative to [`Self::register_kmutex`], and as such incurs a little additional overhead.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - `Grt` has not been initialised, see [`Grt::init`]
    /// - The mutex key already exists
    ///
    /// # Examples
    ///
    /// ```
    /// let result = Grt::register_kmutex_checked("my_test_mutex", 0u32);
    /// ```
    pub fn register_kmutex_checked<T: Any>(label: &'static str, data: T) -> Result<(), GrtError> {
        // Check for a null pointer on the atomic
        let atomic_ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if atomic_ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        // Try initialise a new mutex
        let mtx = Box::new(KMutex::new(data).map_err(|e| GrtError::DriverMutexError(e))?);

        // SAFETY: The atomic pointer is checked at the start of the fn for a nullptr
        unsafe {
            let bucket = (*atomic_ptr).global_kmutex.get(label);
            if bucket.is_some() {
                return Err(GrtError::KeyExists);
            }

            (*atomic_ptr).global_kmutex.insert(label, mtx);
        }

        Ok(())
    }

    /// Register a new [`FastMutex`] for the global reference tracker to control, throwing an error if the key already
    /// exists.
    ///
    /// This is a checked alternative to [`Self::register_fast_mutex`], and as such incurs a little additional overhead.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - `Grt` has not been initialised, see [`Grt::init`]
    /// - The mutex key already exists
    ///
    /// # Examples
    ///
    /// ```
    /// let result = Grt::register_fast_mutex_checked("my_test_mutex", 0u32);
    /// ```
    pub fn register_fast_mutex_checked<T: Any>(
        label: &'static str,
        data: T,
    ) -> Result<(), GrtError> {
        // Check for a null pointer on the atomic
        let atomic_ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if atomic_ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        // Try initialise a new mutex
        let mtx = Box::new(FastMutex::new(data).map_err(|e| GrtError::DriverMutexError(e))?);

        // SAFETY: The atomic pointer is checked at the start of the fn for a nullptr
        unsafe {
            let bucket = (*atomic_ptr).global_kmutex.get(label);
            if bucket.is_some() {
                return Err(GrtError::KeyExists);
            }

            (*atomic_ptr).global_kmutex.insert(label, mtx);
        }

        Ok(())
    }

    /// Retrieve a mutex by name from the `wdk-mutex` global reference tracker.
    ///
    /// This function takes in a static `&str` to lookup your Mutex by key (where the key is the argument). When calling
    /// this function, a turbofish specifier is required to tell the compiler what type is contained in the `Mutex`. See
    /// examples for more information.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - The `Grt` has not been initialised
    /// - The `Grt` is empty
    /// - The key does not exist
    /// - The mutex type is anything other than a [`KMutex`]
    ///
    /// # Examples
    ///
    /// ```
    /// {
    ///     let my_mutex = Grt::get_kmutex::<u32>("my_test_mutex");
    ///     if let Err(e) = my_mutex {
    ///         println!("An error occurred: {:?}", e);
    ///         return;
    ///     }
    ///     let mut lock = my_mutex.unwrap().lock().unwrap();
    ///     *lock += 1;
    /// }
    /// ```
    pub fn get_kmutex<T>(key: &'static str) -> Result<&'static KMutex<T>, GrtError> {
        //
        // Perform checks for erroneous state
        //
        let ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        let grt = unsafe { &(*ptr).global_kmutex };
        if grt.is_empty() {
            return Err(GrtError::GrtIsEmpty);
        }

        let mutex = grt.get(key);
        if mutex.is_none() {
            return Err(GrtError::KeyNotFound);
        }

        //
        // The mutex is valid so obtain a reference to it which can be returned
        //

        // SAFETY: Null pointer and inner null pointers have both been checked in the above lines.
        let m = &**mutex.unwrap();
        let km = m.downcast_ref::<KMutex<T>>();

        if km.is_none() {
            return Err(GrtError::DowncastError);
        }

        Ok(km.unwrap())
    }

    /// Retrieve a mutex by name from the `wdk-mutex` global reference tracker.
    ///
    /// This function takes in a static `&str` to lookup your Mutex by key (where the key is the argument). When calling
    /// this function, a turbofish specifier is required to tell the compiler what type is contained in the `Mutex`. See
    /// examples for more information.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// - The `Grt` has not been initialised
    /// - The `Grt` is empty
    /// - The key does not exist
    /// - The mutex type is anything other than a [`FastMutex`]
    ///
    /// # Examples
    ///
    /// ```
    /// {
    ///     let my_mutex = Grt::get_fast_mutex::<u32>("my_test_mutex");
    ///     if let Err(e) = my_mutex {
    ///         println!("An error occurred: {:?}", e);
    ///         return;
    ///     }
    ///     let mut lock = my_mutex.unwrap().lock().unwrap();
    ///     *lock += 1;
    /// }
    /// ```
    pub fn get_fast_mutex<T>(key: &'static str) -> Result<&'static FastMutex<T>, GrtError> {
        //
        // Perform checks for erroneous state
        //
        let ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        let grt = unsafe { &(*ptr).global_kmutex };
        if grt.is_empty() {
            return Err(GrtError::GrtIsEmpty);
        }

        let mutex = grt.get(key);
        if mutex.is_none() {
            return Err(GrtError::KeyNotFound);
        }

        //
        // The mutex is valid so obtain a reference to it which can be returned
        //

        // SAFETY: Null pointer and inner null pointers have both been checked in the above lines.
        let m = &**mutex.unwrap();
        let km = m.downcast_ref::<FastMutex<T>>();

        if km.is_none() {
            return Err(GrtError::DowncastError);
        }

        Ok(km.unwrap())
    }

    /// Destroy the global reference tracker for `wdk-mutex`.
    ///
    /// Calling [`Self::destroy`] will destroy the 'runtime' provided for using globally accessible `wdk-mutex` mutexes
    /// in your driver.
    ///
    /// # Safety
    ///
    /// Once this function is called you will no longer be able to access any mutexes who's lifetime is managed by the
    /// `Grt`.
    ///
    /// **Note:** This function is marked `unsafe` as it could lead to UB if accidentally used whilst threads / callbacks
    /// dependant upon a mutex that it managed. Although it is `unsafe`, attempting to access a mutex after the `Grt` is destroyed
    /// will not cause a null pointer dereference (they are checked), but it could lead to UB as those setter/getter functions will
    /// return an error.
    ///
    /// # Examples
    ///
    /// ```
    /// /// Driver exit routine
    /// extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    ///     unsafe { Grt::destroy() };
    /// }
    /// ```
    pub unsafe fn destroy() -> Result<(), GrtError> {
        // Check that the static pointer is not already null
        let grt_ptr = WDK_MTX_GRT_PTR.load(SeqCst);
        if grt_ptr.is_null() {
            return Err(GrtError::GrtIsNull);
        }

        // Set the atomic global to null
        WDK_MTX_GRT_PTR.store(null_mut(), SeqCst);

        // Convert the pointer back to a box which wraps the inner `Grt`, allowing Box to drop all it's content
        // which will free all inner memory, drop will properly be called on all Mutexes.
        let _ = unsafe { Box::from_raw(grt_ptr) };

        Ok(())
    }
}
