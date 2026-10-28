//! Peer verification on a terminal (manual §9.1, §12.1, §35).
//!
//! Order of checks, after the handshake authenticated the peer's key:
//! 1. An explicit expected fingerprint (`--to FINGERPRINT`, `--expect`,
//!    `--accept-from`, or the fingerprint carried by a signed LAN beacon for
//!    `--to NAME`) must match, or the peer is rejected.
//! 2. If that fingerprint was given by the user (not just learned from a beacon),
//!    or the peer is in the trust store, it is accepted without a prompt.
//! 3. Otherwise the user compares the 6-digit code on both screens. Without a
//!    terminal there is nobody to ask, so the peer is rejected: there is no
//!    blanket "skip verification" switch.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dfte_core::{PeerAuth, PeerVerifier};

use crate::trust::{TrustStore, normalize_fingerprint};

/// An answer to the SAS question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// Yes, and pin this device so the code isn't asked again.
    Always,
}

/// Parses a typed answer. Empty means the default, No. `None` = unrecognized.
pub fn parse_answer(line: &str) -> Option<Answer> {
    match line.trim().to_lowercase().as_str() {
        "y" | "yes" => Some(Answer::Yes),
        "" | "n" | "no" => Some(Answer::No),
        "a" | "always" => Some(Answer::Always),
        _ => None,
    }
}

/// Which side is asking (only changes the wording).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Send,
    Receive,
}

/// Where an expected fingerprint came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// Nothing known in advance.
    None,
    /// The user typed it (or scanned it): matching it is the verification.
    Pinned(String),
    /// Learned from discovery (signed beacon). It must match, but a name is
    /// not proof of who the user meant, so the SAS is still compared.
    Discovered(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Accept(&'static str),
    Reject(String),
    Ask,
}

/// Pure decision for steps 1–2 (and whether step 3 is possible).
pub fn decide(peer: &PeerAuth, expected: &Expected, trusted: bool, interactive: bool) -> Decision {
    let actual = normalize_fingerprint(&peer.fingerprint);
    let want = match expected {
        Expected::None => None,
        Expected::Pinned(f) | Expected::Discovered(f) => Some(normalize_fingerprint(f)),
    };
    if let Some(w) = want
        && (w.is_none() || w != actual)
    {
        return Decision::Reject(format!(
            "Its fingerprint is {}, not the expected {}.",
            peer.fingerprint,
            match expected {
                Expected::Pinned(f) | Expected::Discovered(f) => f.as_str(),
                Expected::None => "",
            }
        ));
    }
    if matches!(expected, Expected::Pinned(_)) {
        return Decision::Accept("fingerprint matches the one you specified");
    }
    if trusted {
        return Decision::Accept("trusted device");
    }
    if !interactive {
        return Decision::Reject("Cannot ask you to compare the security code because input is not a terminal. Pin the device instead (dfte trust add, or --accept-from / --expect with its fingerprint).".into());
    }
    Decision::Ask
}

/// Terminal verifier. One instance per command; [`PeerVerifier::verify`] runs on
/// a blocking thread inside the engine.
pub struct TerminalVerifier {
    pub role: Role,
    pub expected: Expected,
    pub trust: Arc<Mutex<TrustStore>>,
    pub interactive: bool,
    /// Set while waiting for the user, so Ctrl-C can exit at once.
    pub prompting: Arc<AtomicBool>,
    /// The last peer that passed verification (for later messages).
    pub verified: Arc<Mutex<Option<PeerAuth>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Plain data; a panic elsewhere doesn't make it inconsistent.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl TerminalVerifier {
    fn question(&self, peer: &PeerAuth) -> String {
        let action = match self.role {
            Role::Send => "Send to this device?",
            Role::Receive => "Accept?",
        };
        format!(
            "\n{} \"{}\"\n  fingerprint   {}\n  security code {}\nCheck that the other screen shows the same security code.\n{action} [y]es / [N]o / [a]lways trust this device: ",
            match self.role {
                Role::Send => "Receiving device",
                Role::Receive => "Incoming connection from",
            },
            peer.device_name.chars().filter(|c| !c.is_control()).collect::<String>(),
            peer.fingerprint,
            peer.sas
        )
    }

    fn ask(&self, peer: &PeerAuth) -> std::io::Result<Answer> {
        let mut err = std::io::stderr();
        let stdin = std::io::stdin();
        write!(err, "{}", self.question(peer))?;
        for _ in 0..3 {
            err.flush()?;
            let mut line = String::new();
            if stdin.lock().read_line(&mut line)? == 0 {
                writeln!(err)?;
                return Ok(Answer::No); // EOF: nobody confirmed.
            }
            match parse_answer(&line) {
                Some(a) => return Ok(a),
                None => write!(err, "Please answer y, n or a: ")?,
            }
        }
        Ok(Answer::No)
    }

    fn pin(&self, peer: &PeerAuth) {
        let mut store = lock(&self.trust);
        let saved = match store.add_verified(&peer.fingerprint, &peer.device_name) {
            Ok(p) => Ok(p.name.clone()),
            Err(e) => Err(e),
        }
        .and_then(|name| store.save().map(|()| name));
        match saved {
            Ok(name) => eprintln!("Trusted as \"{name}\"; the code won't be asked again (undo with: dfte trust remove {}).", peer.fingerprint),
            // The connection is verified either way; only the pin failed.
            Err(e) => eprintln!("Could not save the trusted device: {}", e.user_message(None)),
        }
    }
}

impl PeerVerifier for TerminalVerifier {
    fn verify(&self, peer: &PeerAuth) -> bool {
        let trusted = lock(&self.trust).get(&peer.fingerprint).is_some();
        let accepted = match decide(peer, &self.expected, trusted, self.interactive) {
            Decision::Accept(why) => {
                let label = lock(&self.trust).get(&peer.fingerprint).map_or_else(|| peer.device_name.clone(), |p| p.name.clone());
                eprintln!("Connected to \"{label}\" ({}): {why}.", peer.fingerprint);
                true
            }
            Decision::Reject(why) => {
                eprintln!("Rejected {} ({}): {why}", peer.device_name, peer.fingerprint);
                false
            }
            Decision::Ask => {
                self.prompting.store(true, Ordering::SeqCst);
                let answer = self.ask(peer);
                self.prompting.store(false, Ordering::SeqCst);
                match answer {
                    Ok(Answer::Yes) => true,
                    Ok(Answer::Always) => {
                        self.pin(peer);
                        true
                    }
                    Ok(Answer::No) => false,
                    Err(e) => {
                        // Fail closed: an unreadable answer is not a yes.
                        eprintln!("Cannot read your answer ({e}); rejecting the device.");
                        false
                    }
                }
            }
        };
        if accepted {
            *lock(&self.verified) = Some(peer.clone());
        }
        tracing::info!(peer = %peer.fingerprint, accepted, "peer verification");
        accepted
    }
}

/// Whether prompts can be shown. Debug builds let integration tests answer
/// through a pipe (`DFTE_TEST_PROMPT_STDIN=1`); release builds ignore it.
pub fn stdin_is_interactive() -> bool {
    use std::io::IsTerminal;
    if cfg!(debug_assertions) && std::env::var_os("DFTE_TEST_PROMPT_STDIN").is_some_and(|v| v == "1") {
        return true;
    }
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(fp: &str) -> PeerAuth {
        PeerAuth { fingerprint: fp.into(), sas: "123456".into(), device_name: "box".into() }
    }
    const FP: &str = "a1b2-c3d4-e5f6-0718-293a-4b5c";
    const OTHER: &str = "0000-1111-2222-3333-4444-5555";

    #[test]
    fn answers() {
        assert_eq!(parse_answer("y\n"), Some(Answer::Yes));
        assert_eq!(parse_answer(" YES "), Some(Answer::Yes));
        assert_eq!(parse_answer("\n"), Some(Answer::No));
        assert_eq!(parse_answer("no"), Some(Answer::No));
        assert_eq!(parse_answer("a"), Some(Answer::Always));
        assert_eq!(parse_answer("Always"), Some(Answer::Always));
        assert_eq!(parse_answer("yep"), None);
        assert_eq!(parse_answer("123456"), None, "typing the code is not a yes");
    }

    #[test]
    fn decisions() {
        let p = peer(FP);
        assert_eq!(decide(&p, &Expected::Pinned(FP.to_uppercase()), false, false), Decision::Accept("fingerprint matches the one you specified"));
        assert!(matches!(decide(&p, &Expected::Pinned(OTHER.into()), true, true), Decision::Reject(_)), "pin mismatch wins over trust");
        assert!(matches!(decide(&p, &Expected::Pinned("garbage".into()), false, true), Decision::Reject(_)));
        assert!(matches!(decide(&p, &Expected::Discovered(OTHER.into()), true, true), Decision::Reject(_)));
        assert_eq!(decide(&p, &Expected::Discovered(FP.into()), false, true), Decision::Ask, "a name match still needs the SAS");
        assert_eq!(decide(&p, &Expected::Discovered(FP.into()), true, false), Decision::Accept("trusted device"));
        assert_eq!(decide(&p, &Expected::None, true, false), Decision::Accept("trusted device"));
        assert_eq!(decide(&p, &Expected::None, false, true), Decision::Ask);
        assert!(matches!(decide(&p, &Expected::None, false, false), Decision::Reject(_)), "no terminal, no pin: reject");
    }
}
