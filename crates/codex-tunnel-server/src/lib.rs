pub mod config;

#[cfg(test)]
mod tests {
    use codex_tunnel::MAX_SERVER_STATIC_IDENTITIES;

    use super::config::ServerConfig;

    #[test]
    fn destination_must_be_a_fixed_loopback_address() {
        let text = r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "192.0.2.7:22"
            [identity]
            private_key_file = "/tmp/server.key"
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let error = ServerConfig::from_toml(text).expect_err("must not become a general proxy");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn accepts_tls_with_a_certificate_and_private_key() {
        let text = r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "127.0.0.1:8787"
            [identity]
            private_key_file = "/tmp/server.key"
            [outer_tls]
            enabled = true
            certificate_file = "/tmp/cert.pem"
            private_key_file = "/tmp/tls.key"
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        assert!(ServerConfig::from_toml(text).is_ok());
    }

    #[test]
    fn tls_requires_a_certificate_and_private_key() {
        let text = r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "127.0.0.1:8787"
            [identity]
            private_key_file = "/tmp/server.key"
            [outer_tls]
            enabled = true
            certificate_file = "/tmp/cert.pem"
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let error = ServerConfig::from_toml(text).expect_err("TLS needs a key");
        assert!(error.to_string().contains("private_key_file"));
    }

    #[test]
    fn accepts_a_bounded_server_static_key_overlap() {
        let text = r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "127.0.0.1:8787"
            [identity]
            private_key_file = "/tmp/server-current.key"
            additional_private_key_files = ["/tmp/server-rotated.key"]
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let config = ServerConfig::from_toml(text).expect("valid overlap configuration");
        assert_eq!(config.identity.additional_private_key_files.len(), 1);
    }

    #[test]
    fn rejects_an_unbounded_or_duplicate_server_static_key_overlap() {
        let additional = (0..MAX_SERVER_STATIC_IDENTITIES)
            .map(|number| format!("\"/tmp/server-{number}.key\""))
            .collect::<Vec<_>>()
            .join(", ");
        let text = format!(
            r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "127.0.0.1:8787"
            [identity]
            private_key_file = "/tmp/server-current.key"
            additional_private_key_files = [{additional}]
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#
        );
        let error = ServerConfig::from_toml(&text).expect_err("overlap must be bounded");
        assert!(error.to_string().contains("at most"));

        let duplicate = text.replace(
            &format!("additional_private_key_files = [{additional}]"),
            "additional_private_key_files = [\"/tmp/server-current.key\"]",
        );
        let error = ServerConfig::from_toml(&duplicate).expect_err("keys must be distinct");
        assert!(error.to_string().contains("distinct"));
    }

    #[test]
    fn rejects_a_connection_limit_above_the_safe_ceiling() {
        let text = r#"
            [listen]
            address = "127.0.0.1:8443"
            [destination]
            address = "127.0.0.1:8787"
            [identity]
            private_key_file = "/tmp/server.key"
            [[authorized_clients]]
            name = "mac"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [limits]
            max_connections = 1025
            max_plaintext_record_bytes = 16384
        "#;
        let error = ServerConfig::from_toml(text).expect_err("unbounded ingress work is unsafe");
        assert!(error.to_string().contains("1024"));
    }
}
