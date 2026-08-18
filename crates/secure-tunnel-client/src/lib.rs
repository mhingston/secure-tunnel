pub mod config;

#[cfg(test)]
mod tests {
    use super::config::ClientConfig;

    #[test]
    fn rejects_a_non_loopback_listener() {
        let text = r#"
            [listen]
            address = "0.0.0.0:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let error = ClientConfig::from_toml(text).expect_err("public listener is unsafe");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn accepts_the_documented_loopback_default_port() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        assert!(ClientConfig::from_toml(text).is_ok());
    }

    #[test]
    fn accepts_tls_when_a_server_name_is_supplied() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [outer_tls]
            enabled = true
            server_name = "example.test"
        "#;
        assert!(ClientConfig::from_toml(text).is_ok());
    }

    #[test]
    fn tls_requires_a_server_name() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [outer_tls]
            enabled = true
        "#;
        let error = ClientConfig::from_toml(text).expect_err("TLS must verify a DNS name");
        assert!(error.to_string().contains("server_name"));
    }

    #[test]
    fn accepts_an_explicit_test_ca_with_tls() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [outer_tls]
            enabled = true
            server_name = "example.test"
            additional_ca_file = "/tmp/test-ca.pem"
        "#;
        assert!(ClientConfig::from_toml(text).is_ok());
    }

    #[test]
    fn rejects_a_zero_connection_limit() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [limits]
            max_connections = 0
        "#;
        let error = ClientConfig::from_toml(text).expect_err("zero must not disable the bound");
        assert!(error.to_string().contains("connection limit"));
    }

    #[test]
    fn rejects_a_connection_limit_above_the_safe_ceiling() {
        let text = r#"
            [listen]
            address = "127.0.0.1:18787"
            [remote]
            address = "example.test:8443"
            [identity]
            private_key_file = "/tmp/client.key"
            [peer]
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [limits]
            max_connections = 1025
        "#;
        let error = ClientConfig::from_toml(text).expect_err("unbounded local work is unsafe");
        assert!(error.to_string().contains("1024"));
    }
}
