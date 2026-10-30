//! `dfte-gtk`: the Linux desktop app (manual §2.2, §24): GTK4 + libadwaita calling
//! the Rust core directly, no FFI boundary (§1.3). Layout and tokens follow
//! `.claude/design/ui-spec.html` ("Desktop layout").

#[cfg(target_os = "linux")]
mod app;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod text;

#[cfg(target_os = "linux")]
fn main() -> gtk::glib::ExitCode {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_env("DFTE_LOG").unwrap_or_else(|_| "warn".into())).with_writer(std::io::stderr).init();
    app::run()
}

/// GTK is the Linux front end; Windows (WinUI 3) and macOS have their own (§2.2).
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("dfte-gtk is the Linux desktop app; use the platform's own app or the `dfte` CLI here.");
}
