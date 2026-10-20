//! Text from untrusted sources (web addresses, filenames) that is shown in
//! the trusted UI.

/// Unicode's format characters (general category Cf, Unicode 16.0
/// DerivedGeneralCategory.txt): bidirectional controls, zero-width and
/// joining characters, invisible operators, tag characters and the like.
/// None is drawn as itself; in a trusted message they could reorder, hide or
/// smuggle web-supplied text so that it appears to be Rift's own wording.
/// The whole category, so that a control left off a hand-made list (the
/// Arabic letter mark, the word joiner, tag characters were) cannot slip by.
const FORMAT: &[(char, char)] = &[
    ('\u{00ad}', '\u{00ad}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{06dd}', '\u{06dd}'),
    ('\u{070f}', '\u{070f}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08e2}', '\u{08e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// A control character (Cc) or a format character (Cf).
pub(crate) fn is_hidden_or_control(c: char) -> bool {
    c.is_control() || FORMAT.iter().any(|&(first, last)| (first..=last).contains(&c))
}

/// Makes web-derived text safe to embed in a trusted sentence: control,
/// bidirectional and invisible characters are shown as `\u{…}` escapes
/// instead of acting on the surrounding text. Everything else is unchanged,
/// so the user still sees what the site supplied.
pub fn escape_for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_or_control(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// A bounded plain-text view of untrusted file content (§11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainText {
    pub text: String,
    /// The content was longer than the limit; only its start is shown.
    pub truncated: bool,
    /// Invalid UTF-8 was shown as U+FFFD.
    pub replaced: bool,
}

/// How far into the content a NUL byte marks it as binary rather than text.
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Decodes at most `limit` bytes of `content` as UTF-8 to be shown as plain
/// text, never interpreted. Invalid sequences become U+FFFD. Line breaks and
/// tabs are kept (CRLF becomes LF); every other control, bidirectional or
/// invisible character is shown as an escape, so it cannot reorder or hide
/// the text around it. Returns `None` for content that looks binary (a NUL
/// byte near the start).
pub fn plain_text(content: &[u8], limit: usize) -> Option<PlainText> {
    let head = content.get(..BINARY_SNIFF_BYTES).unwrap_or(content);
    if head.contains(&0) {
        return None;
    }
    let truncated = content.len() > limit;
    let mut end = content.len().min(limit);
    if truncated {
        // Cut before a character, not inside one (at most three continuation bytes).
        for _ in 0..3 {
            match (content.get(end), end.checked_sub(1)) {
                (Some(b), Some(before)) if b & 0xc0 == 0x80 => end = before,
                _ => break,
            }
        }
    }
    let decoded = String::from_utf8_lossy(content.get(..end).unwrap_or_default());
    let replaced = matches!(decoded, std::borrow::Cow::Owned(_));
    let mut text = String::with_capacity(decoded.len());
    let mut chars = decoded.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' | '\t' => text.push(c),
            '\r' if chars.peek() == Some(&'\n') => {}
            c if is_hidden_or_control(c) => text.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
            c => text.push(c),
        }
    }
    Some(PlainText {
        text,
        truncated,
        replaced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_bounded_and_cannot_reorder_itself() {
        let shown = plain_text(b"line 1\r\n\tline 2\x1b[31m red \xe2\x80\xae evil", 1024).unwrap();
        assert_eq!(shown.text, "line 1\n\tline 2\\u{1b}[31m red \\u{202e} evil");
        assert!(!shown.truncated && !shown.replaced);

        // Invalid UTF-8 is replaced, and a cut never splits a character.
        let shown = plain_text(b"ok \xff", 1024).unwrap();
        assert_eq!(shown.text, "ok \u{fffd}");
        assert!(shown.replaced);
        let shown = plain_text("aé€".as_bytes(), 4).unwrap();
        assert_eq!(shown.text, "aé");
        assert!(shown.truncated && !shown.replaced);

        // Binary content is not shown as text.
        assert_eq!(plain_text(b"MZ\x90\x00\x03", 1024), None);
        assert!(plain_text(b"", 1024).is_some());
    }

    #[test]
    fn reordering_and_control_characters_are_made_visible() {
        assert_eq!(
            escape_for_display("pay\u{202e}lap.com\n"),
            "pay\\u{202e}lap.com\\u{a}"
        );
        assert_eq!(escape_for_display("bücher.example"), "bücher.example");
        assert_eq!(escape_for_display("a\u{200b}b"), "a\\u{200b}b");
    }

    #[test]
    fn every_format_character_is_made_visible() {
        // Arabic letter mark (a bidi control), word joiner, soft hyphen,
        // a tag character (invisible, used to smuggle text) and the
        // deprecated shaping controls: all category Cf, none in the first list.
        for c in ['\u{61c}', '\u{2060}', '\u{ad}', '\u{e0041}', '\u{206a}', '\u{fff9}'] {
            let text = format!("a{c}b");
            assert_eq!(escape_for_display(&text), format!("a\\u{{{:x}}}b", u32::from(c)));
            assert_eq!(plain_text(text.as_bytes(), 64).unwrap().text, format!("a\\u{{{:x}}}b", u32::from(c)));
        }
        // Letters around the ranges stay as they are.
        assert_eq!(escape_for_display("\u{5ff}\u{606}\u{2065}\u{e0080}"), "\u{5ff}\u{606}\u{2065}\u{e0080}");
    }
}
