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

#[cfg(test)]
mod tests {
    use super::*;

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
