# Legal documents

These are drafts. No lawyer has reviewed them. Get them checked before relying on them, especially before a Play Store release.

What each file is for:

- [privacy.md](privacy.md) is the privacy policy. It can be linked from the Play Store listing and from the apps. It describes what DFTE stores on the device, what nearby devices can see, and why each Android permission is needed.
- [terms.md](terms.md) is the terms of use for the apps. It points to [LICENSE](../../LICENSE) for the actual license and doesn't change it.
- [third-party-notices.md](third-party-notices.md) lists the Rust crates, Android libraries, fonts and Linux system libraries DFTE uses, with their licenses. The crate tables are generated.
- [gen_third_party.py](gen_third_party.py) regenerates those tables from `cargo metadata`. The commands are at the top of the notices file.
- The security policy is [SECURITY.md](../../SECURITY.md) in the repository root, where GitHub looks for it.

Decided so far:

- Governing law is the law of the Republic of Türkiye, with the courts and enforcement offices of Samsun having jurisdiction. Consumers keep any protections their own country's law doesn't let them give up.
- The terms are an agreement with Yazdan Samari as an individual, not a company.
- The privacy policy says the developer receives no personal data from the apps, and covers KVKK (Law No. 6698) and GDPR in one short section.

Still open for the owner:

- Turn on private vulnerability reporting in the GitHub repository settings (Security, then Private vulnerability reporting). SECURITY.md relies on it.
- Decide on a private contact, such as an email address, for privacy requests and legal notices. Right now the only contact is public GitHub issues.
- Have a lawyer check the liability and consumer wording against Turkish law (Turkish Code of Obligations article 115, Consumer Protection Law No. 6502) and against EU consumer law, and check whether the Samsun jurisdiction clause holds for consumers.

When the code changes, check these files against it. The privacy policy names real paths, permissions and announcement fields, so it goes out of date if any of those change: for example a new Android permission in `platform/android/app/src/main/AndroidManifest.xml`, a new field in the LAN announcement (`crates/discovery/src/lan/beacon.rs`), or a new file the apps keep on disk. Regenerate the crate list after any change to `Cargo.lock`.
