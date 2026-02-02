#[cfg(test)]
mod tests {
    use redmi_tls::TokenManager;
    use std::env;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_validate_persistent() {
        let tmp = NamedTempFile::new().expect("tmpfile");
        let path = tmp.path().to_owned();
        env::set_var("TOKEN_STORE", path.to_str().unwrap());

        let tm = TokenManager::new("master_key_for_test", "other_test");
        let tok = tm.generate("ctx-test", 2).expect("generate");
        assert!(tm.validate_with_context(&tok, "ctx-test"));

        let tm2 = TokenManager::new("master_key_for_test", "other_test");
        assert!(tm2.validate_with_context(&tok, "ctx-test"));

        redmi_tls::time_abstraction::kernel_time_advance(3);
        let tm3 = TokenManager::new("master_key_for_test", "other_test");
        assert!(!tm3.validate_with_context(&tok, "ctx-test"));
    }
}
