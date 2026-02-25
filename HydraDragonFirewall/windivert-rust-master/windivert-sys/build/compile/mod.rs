use cc::Build;

mod gnu;
mod msvc;

pub fn lib() {
    if Build::new().get_compiler().is_like_gnu() {
        return gnu::lib();
    }

    msvc::lib();
}

pub fn dll() {
    if Build::new().get_compiler().is_like_gnu() {
        return gnu::dll();
    }
    msvc::dll();
}
