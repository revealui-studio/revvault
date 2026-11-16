/// A previous copy must not expire a newer copy or unrelated clipboard content.
pub fn should_clear(ticket: u64, generation: u64, copied: &str, current: &str) -> bool {
    ticket == generation && copied == current
}

#[cfg(test)]
mod tests {
    use super::should_clear;

    #[test]
    fn clears_unchanged_owned_content() {
        assert!(should_clear(1, 1, "owned", "owned"));
    }

    #[test]
    fn preserves_other_application_content() {
        assert!(!should_clear(1, 1, "owned", "new content"));
    }

    #[test]
    fn later_copy_of_same_value_renews_expiry() {
        assert!(!should_clear(1, 2, "owned", "owned"));
        assert!(should_clear(2, 2, "owned", "owned"));
    }
}
