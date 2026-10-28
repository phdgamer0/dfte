#![no_main]
//! Untrusted manifests and path strings (manual §33/§35).

use libfuzzer_sys::fuzz_target;
use protocol::Manifest;
use protocol::manifest::validate_relative_path;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Manifest::decode(data) {
        for f in &m.files {
            assert!(!f.relative_path.split('/').any(|c| c == ".." || c.is_empty()));
            assert!(!f.relative_path.starts_with('/'));
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if validate_relative_path(s).is_ok() {
            assert!(!s.contains(['\0', '\\']) && !s.split('/').any(|c| c == ".."));
        }
    }
});
