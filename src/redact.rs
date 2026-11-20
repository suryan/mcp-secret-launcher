//! Redact exact secret values (and their base64 forms) from captured output.

use secrecy::{ExposeSecret, SecretString};

/// Standard base64 alphabet encode (no padding strip; includes `=` padding).
#[must_use]
pub fn b64_encode(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = u32::from(bytes[i]);
        let b1 = if i + 1 < bytes.len() {
            u32::from(bytes[i + 1])
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            u32::from(bytes[i + 2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Replace every occurrence of each secret value and its base64 form with `[REDACTED]`.
///
/// Empty values are skipped (would otherwise wipe the whole string). Longer values are
/// applied first so a substring of another secret cannot leave a partial leak.
#[must_use]
pub fn redact_output(text: &str, secrets: &[SecretString]) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for s in secrets {
        let v = s.expose_secret();
        if v.is_empty() {
            continue;
        }
        pairs.push((v.to_string(), b64_encode(v)));
    }
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let mut out = text.to_string();
    for (raw, b64) in pairs {
        if out.contains(&raw) {
            out = out.replace(&raw, "[REDACTED]");
        }
        if out.contains(&b64) {
            out = out.replace(&b64, "[REDACTED]");
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn b64_known_vector() {
        assert_eq!(b64_encode("hello"), "aGVsbG8=");
        assert_eq!(b64_encode(""), "");
        assert_eq!(b64_encode("f"), "Zg==");
    }

    #[test]
    fn redacts_raw_and_b64() {
        let secret = SecretString::from("super-secret-value");
        let b64 = b64_encode("super-secret-value");
        let text = format!("token=super-secret-value b64={b64} ok");
        let out = redact_output(&text, &[secret]);
        assert!(!out.contains("super-secret-value"));
        assert!(!out.contains(&b64));
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("ok"));
    }

    #[test]
    fn skips_empty_secrets() {
        let out = redact_output("hello", &[SecretString::from("")]);
        assert_eq!(out, "hello");
    }
}
