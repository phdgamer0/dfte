//! User-facing strings, kept free of GTK so they can be unit-tested.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use dfte_cli::progress::{human_bytes, human_duration, human_rate};
use dfte_core::{IncomingOffer, Transfer, TransferState};

/// "1.1 GiB of 1.8 GiB · 63%".
pub fn progress_line(done: u64, total: u64) -> String {
    let pct = done.saturating_mul(100).checked_div(total).map_or(100, |p| p.min(100));
    format!("{} of {} · {pct}%", human_bytes(done), human_bytes(total))
}

/// "29.4 MiB/s · 24 s left", or "" while there is no rate yet.
pub fn rate_line(t: &Transfer) -> String {
    if t.throughput_bytes_per_sec == 0 {
        return String::new();
    }
    let left = t.bytes_total.saturating_sub(t.bytes_done) / t.throughput_bytes_per_sec.max(1);
    format!("{} · {} left", human_rate(t.throughput_bytes_per_sec as f64), human_duration(Duration::from_secs(left)))
}

pub fn state_label(s: TransferState) -> &'static str {
    match s {
        TransferState::Pending => "Waiting",
        TransferState::Negotiating => "Connecting",
        TransferState::Transferring => "Transferring",
        TransferState::Paused => "Paused",
        TransferState::Interrupted => "Interrupted",
        TransferState::Completed => "Done",
        TransferState::Cancelled => "Cancelled",
        TransferState::Failed(_) => "Failed",
    }
}

/// "3 items · 1.8 GiB" / "1 item · 12 KiB".
pub fn items(count: usize, bytes: u64) -> String {
    format!("{count} item{} · {}", if count == 1 { "" } else { "s" }, human_bytes(bytes))
}

/// Heading and body of the incoming-offer dialog. The peer's name is
/// self-reported, so the fingerprint stays visible (manual §35).
pub fn offer_text(o: &IncomingOffer) -> (String, String) {
    let name = dfte_cli::offer::printable(&o.peer_name);
    let mut body = format!("{}\n", items(o.files.iter().filter(|f| !f.is_dir).count(), o.bytes_total));
    for f in o.files.iter().filter(|f| !f.is_dir).take(5) {
        body.push_str(&format!("\n{}  ({})", dfte_cli::offer::printable(&f.path), human_bytes(f.size)));
    }
    let more = o.files.iter().filter(|f| !f.is_dir).count().saturating_sub(5);
    if more > 0 {
        body.push_str(&format!("\n…and {more} more"));
    }
    body.push_str(&format!("\n\nFrom {}", o.peer_fingerprint));
    (format!("{name} wants to send you files"), body)
}

/// The six SAS digits for the code boxes; anything that isn't a digit is dropped.
pub fn sas_digits(sas: &str) -> Vec<char> {
    sas.chars().filter(char::is_ascii_digit).collect()
}

/// This machine's address on the default route: what a sender on the same
/// network types. Sends nothing (a connected UDP socket only picks a route).
pub fn default_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Initials for a device avatar: "Work laptop" -> "WL".
pub fn initials(name: &str) -> String {
    let s: String = name.split([' ', '-', '_']).filter(|w| !w.is_empty()).take(2).filter_map(|w| w.chars().next()).flat_map(char::to_uppercase).collect();
    if s.is_empty() { "?".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfte_core::OfferedFile;

    #[test]
    fn progress_and_items() {
        assert_eq!(progress_line(0, 0), "0 B of 0 B · 100%");
        assert!(progress_line(512, 1024).ends_with("· 50%"));
        assert_eq!(items(1, 0), "1 item · 0 B");
        assert!(items(3, 2048).starts_with("3 items · "));
    }

    #[test]
    fn offer_lists_files_and_keeps_the_fingerprint() {
        let files = (0..7).map(|i| OfferedFile { path: format!("f{i}.bin"), size: 10, is_dir: false }).chain([OfferedFile { path: "d".into(), size: 0, is_dir: true }]).collect();
        let o = IncomingOffer { transfer_id: "t".into(), peer_fingerprint: "aaaa-bbbb".into(), peer_name: "Phone\u{1b}[31m".into(), files, bytes_total: 70 };
        let (head, body) = offer_text(&o);
        assert!(!head.contains('\u{1b}'), "control characters are not shown: {head:?}");
        assert!(body.starts_with("7 items"), "{body}");
        assert!(body.contains("…and 2 more"));
        assert!(body.contains("aaaa-bbbb"));
    }

    #[test]
    fn sas_and_initials() {
        assert_eq!(sas_digits("482 913"), vec!['4', '8', '2', '9', '1', '3']);
        assert_eq!(initials("Work laptop"), "WL");
        assert_eq!(initials("archlinux"), "A");
        assert_eq!(initials(" "), "?");
    }

    #[test]
    fn rate_line_needs_a_rate() {
        let mut t = Transfer { id: "x".into(), direction: dfte_core::Direction::Send, state: TransferState::Transferring, transport: transport::TransportKind::Tcp, bytes_total: 100 << 20, bytes_done: 50 << 20, resumed_bytes: 0, throughput_bytes_per_sec: 0, peer_fingerprint: None, peer_name: None };
        assert_eq!(rate_line(&t), "");
        t.throughput_bytes_per_sec = 10 << 20;
        assert!(rate_line(&t).ends_with("left"), "{}", rate_line(&t));
    }
}
