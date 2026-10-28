//! uniffi's binding generator, pinned to the same uniffi version as the
//! library. Usage (library mode):
//! `cargo run -p platform-ffi --features bindgen --bin uniffi-bindgen -- generate --library <libplatform_ffi.so> --language kotlin --out-dir <dir>`

fn main() {
    uniffi::uniffi_bindgen_main()
}
