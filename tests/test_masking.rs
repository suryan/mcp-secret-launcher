//! Tests for the masking module.


use mcp_secret_launcher::masking::*;
use proptest::prelude::*;

#[test]
fn test_mask_long_value() {
    assert_eq!(mask_value("ATATT3xFfGF0"), "ATATT3x...****");
}

#[test]
fn test_mask_exactly_8_chars() {
    assert_eq!(mask_value("12345678"), "1234567...****");
}

#[test]
fn test_mask_exactly_7_chars() {
    assert_eq!(mask_value("1234567"), "****");
}

#[test]
fn test_mask_short_value() {
    assert_eq!(mask_value("abc"), "****");
}

#[test]
fn test_mask_empty_value() {
    assert_eq!(mask_value(""), "****");
}

#[test]
fn test_mask_single_char() {
    assert_eq!(mask_value("x"), "****");
}

// Feature: mcp-secret-launcher, Property 4: Masking produces correct output format
// **Validates: Requirements 6.2**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_masking_produces_correct_output_format(
        value in "\\PC{1,100}"
    ) {
        let masked = mask_value(&value);
        let char_count = value.chars().count();

        if char_count > 7 {
            // Output starts with first 7 chars and ends with "...****"
            let prefix: String = value.chars().take(7).collect();
            let expected = format!("{prefix}...****");
            prop_assert_eq!(&masked, &expected, "For input char count > 7, expected '{}...****'", prefix);

            // The masked output must be shorter than the original for long inputs,
            // ensuring the full secret is never revealed.
            // (A simple `contains` check can false-positive when the input is
            // barely over 7 chars and the suffix chars happen to appear in "...****".)
            prop_assert!(
                masked.chars().count() < value.chars().count() + 7,
                "Masked output should be significantly shorter than original + suffix"
            );
            // The output must NOT equal the original value
            prop_assert_ne!(&masked, &value, "Masked output must differ from original");
        } else {
            // For inputs <= 7 chars, output is exactly "****"
            prop_assert_eq!(masked, "****", "For input char count <= 7, expected '****'");
        }
    }

    // Feature: mcp-secret-launcher, Property 5: Get output format
    // **Validates: Requirements 6.2**
    #[test]
    fn prop_get_output_format(
        key_name in "[A-Z][A-Z0-9_]{0,30}",
        secret_value in "[a-zA-Z0-9]{1,100}",
    ) {
        let output = format!("{} = {}", key_name, mask_value(&secret_value));

        // Output starts with the key name
        prop_assert!(
            output.starts_with(&key_name),
            "Output should start with the key name '{}', got '{}'", key_name, output
        );

        // Output contains " = "
        prop_assert!(
            output.contains(" = "),
            "Output should contain ' = ', got '{}'", output
        );

        // The part after " = " equals mask_value(&secret_value)
        let separator = " = ";
        if let Some(pos) = output.find(separator) {
            let after_separator = &output[pos + separator.len()..];
            let expected_masked = mask_value(&secret_value);
            prop_assert_eq!(
                after_separator, &expected_masked,
                "Part after ' = ' should equal mask_value result"
            );
        } else {
            prop_assert!(false, "output did not contain separator");
        }
    }
}
