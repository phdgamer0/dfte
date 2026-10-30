# Legal documents

These are drafts. No lawyer has reviewed them. Get them checked before relying on them, especially before a Play Store release.

What each file is for:

- [privacy.md](privacy.md) is the privacy policy. It can be linked from the Play Store listing and from the apps. It describes what DFTE stores on the device, what nearby devices can see, and why each Android permission is needed.
- [terms.md](terms.md) is the terms of use for the apps. It points to [LICENSE](../../LICENSE) for the actual license and doesn't change it. The governing law section is a placeholder the owner has to fill in.
- [third-party-notices.md](third-party-notices.md) lists the Rust crates, Android libraries, fonts and Linux system libraries DFTE uses, with their licenses. The crate tables are generated.
- [gen_third_party.py](gen_third_party.py) regenerates those tables from `cargo metadata`. The commands are at the top of the notices file.
- The security policy is [SECURITY.md](../../SECURITY.md) in the repository root, where GitHub looks for it.

When the code changes, check these files against it. The privacy policy names real paths, permissions and announcement fields, so it goes out of date if any of those change: for example a new Android permission in `platform/android/app/src/main/AndroidManifest.xml`, a new field in the LAN announcement (`crates/discovery/src/lan/beacon.rs`), or a new file the apps keep on disk. Regenerate the crate list after any change to `Cargo.lock`.
