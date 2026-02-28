/// Produces a masked representation of a secret value.
///
/// - If the input is longer than 7 characters: returns the first 7 characters followed by `...****`
/// - If the input is 7 characters or fewer: returns `****`
pub fn mask_value(value: &str) -> String {
    let char_count = value.chars().count();
    if char_count > 7 {
        let prefix: String = value.chars().take(7).collect();
        format!("{prefix}...****")
    } else {
        "****".to_string()
    }
}
