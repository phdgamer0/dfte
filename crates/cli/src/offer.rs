//! Describing an incoming manifest before anything is written (manual §35).

use std::collections::BTreeMap;

use dfte_core::Manifest;

use crate::progress::human_bytes;

/// One top-level entry of an offer: a file, or a folder with its totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopEntry {
    pub name: String,
    pub is_folder: bool,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSummary {
    pub files: usize,
    pub bytes: u64,
    /// Largest first.
    pub top: Vec<TopEntry>,
}

/// Strip control characters (incl. ESC) so a peer-chosen name can't drive the terminal.
pub fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

pub fn summarize(m: &Manifest) -> OfferSummary {
    let mut top: BTreeMap<String, TopEntry> = BTreeMap::new();
    let mut files = 0;
    for f in &m.files {
        if !f.is_dir {
            files += 1;
        }
        let (first, rest) = match f.relative_path.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (f.relative_path.as_str(), None),
        };
        let e = top.entry(first.to_owned()).or_insert_with(|| TopEntry { name: printable(first), is_folder: false, files: 0, bytes: 0 });
        e.is_folder |= rest.is_some() || f.is_dir;
        e.files += usize::from(!f.is_dir);
        e.bytes += f.size;
    }
    let mut top: Vec<TopEntry> = top.into_values().collect();
    top.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    OfferSummary { files, bytes: m.total_bytes(), top }
}

/// Multi-line description, at most `max_lines` entries.
pub fn describe(s: &OfferSummary, max_lines: usize) -> String {
    let mut out = format!("{} file{}, {} total", s.files, if s.files == 1 { "" } else { "s" }, human_bytes(s.bytes));
    for e in s.top.iter().take(max_lines) {
        if e.is_folder {
            out.push_str(&format!("\n  {}/  ({} file{}, {})", e.name, e.files, if e.files == 1 { "" } else { "s" }, human_bytes(e.bytes)));
        } else {
            out.push_str(&format!("\n  {}  ({})", e.name, human_bytes(e.bytes)));
        }
    }
    if s.top.len() > max_lines {
        out.push_str(&format!("\n  …and {} more", s.top.len() - max_lines));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfte_core::FileEntry;

    #[test]
    fn groups_top_level_and_sorts_by_size() {
        let files = vec![FileEntry::file("photos/a.jpg", 10, [1; 32]).unwrap(), FileEntry::file("photos/b/c.jpg", 20, [2; 32]).unwrap(), FileEntry::dir("photos/empty"), FileEntry::file("notes.txt", 5, [3; 32]).unwrap(), FileEntry::file("big.iso", 100, [4; 32]).unwrap(), FileEntry::dir("emptydir")];
        let m = Manifest::new(files).unwrap();
        let s = summarize(&m);
        assert_eq!(s.files, 4);
        assert_eq!(s.bytes, 135);
        let names: Vec<&str> = s.top.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["big.iso", "photos", "notes.txt", "emptydir"]);
        assert!(s.top[1].is_folder && s.top[1].files == 2);
        assert!(s.top[3].is_folder && s.top[3].files == 0);
        let text = describe(&s, 2);
        assert!(text.starts_with("4 files, 135 B total"), "{text}");
        assert!(text.contains("photos/  (2 files, 30 B)"), "{text}");
        assert!(text.ends_with("…and 2 more"), "{text}");
    }

    #[test]
    fn control_characters_are_neutralized() {
        assert_eq!(printable("a\u{1b}[2Jb\n"), "a?[2Jb?");
    }
}
