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
const USAGE: &str = "\
Usage: dfte-gtk [--page PAGE] [FILE...]

DFTE desktop app: send files straight to a nearby device, no cloud.

  --page PAGE   open on send, receive, activity, devices or settings
  FILE...       files or folders to send (preselected on the Send page)
  -h, --help    print this help
  -V, --version print the version

Environment: DFTE_DEVICE_NAME (name shown to others), DFTE_LOG (log filter,
default warn). Identity, trusted devices and partial transfers are shared with
the dfte command-line tool ($XDG_DATA_HOME/dfte).
";

#[cfg(target_os = "linux")]
fn main() -> gtk::glib::ExitCode {
    // Answered before GTK starts: GApplication would otherwise hand these to a
    // running instance or open a window.
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return gtk::glib::ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("dfte-gtk {}", env!("CARGO_PKG_VERSION"));
                return gtk::glib::ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_env("DFTE_LOG").unwrap_or_else(|_| "warn".into())).with_writer(std::io::stderr).init();
    app::run()
}

/// GTK is the Linux front end; Windows (WinUI 3) and macOS have their own (§2.2).
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("dfte-gtk is the Linux desktop app; use the platform's own app or the `dfte` CLI here.");
}
