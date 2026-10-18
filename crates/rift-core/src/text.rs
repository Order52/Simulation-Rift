//! Text from untrusted sources (web addresses, filenames) that is shown in
//! the trusted UI.

/// Characters that reorder or hide text. In a trusted message they could make
/// web-supplied text appear to be part of Rift's own wording.
const BIDI_AND_INVISIBLE: &[char] = &[
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}',
    '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}',
];

pub(crate) fn is_hidden_or_control(c: char) -> bool {
    c.is_control() || BIDI_AND_INVISIBLE.contains(&c)
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
}
