use bitcoin::Network;
use redact::Secret;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RpcConfig {
    pub network: Network,
    pub url: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub wallet: String,
}

impl RpcConfig {
    pub fn new(
        network: Network,
        url: String,
        username: String,
        password: String,
        wallet: String,
    ) -> Self {
        Self {
            network,
            url: Secret::new(url),
            username: Secret::new(username),
            password: Secret::new(password),
            wallet,
        }
    }
}

/// Masks potential secrets in URLs by replacing high-entropy strings with asterisks
pub(crate) fn mask_url_secrets(url: &str) -> String {
    let mut masked_url = url.to_string();

    // Split the URL into parts to avoid masking legitimate parts like hostnames
    let parts: Vec<&str> = url.split(&['/', '?', '&', '=', ':', '@'][..]).collect();

    for part in parts {
        // Check if this part looks like a secret (high entropy string)
        if is_potential_secret(part) {
            // Replace the secret with asterisks of the same length
            let asterisks = "*".repeat(part.len());
            masked_url = masked_url.replace(part, &asterisks);
        }
    }

    masked_url
}

/// Determines if a string might be a secret based on entropy characteristics
fn is_potential_secret(s: &str) -> bool {
    // Skip very short strings and common words
    if s.len() < 16 {
        return false;
    }

    // Skip common URL components
    if matches!(
        s.to_lowercase().as_str(),
        "http" | "https" | "localhost" | "127.0.0.1" | "wallet" | "bitcoin" | "rpc" | "api"
    ) {
        return false;
    }

    // Check for hexadecimal patterns (common in secrets/tokens)
    let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    let total_chars = s.len();

    // If more than 80% of characters are hex and string is long enough, likely a secret
    if hex_chars as f64 / total_chars as f64 > 0.8 && total_chars >= 16 {
        return true;
    }

    // Check for base64-like patterns (alphanumeric with some special chars)
    let alphanum_chars = s.chars().filter(|c| c.is_alphanumeric()).count();
    alphanum_chars as f64 / total_chars as f64 > 0.9 && total_chars >= 20
}

#[cfg(test)]
mod tests {
    use super::*;

    // The URL and the credentials are kept as secrets, so printing the config does not show them.
    #[test]
    fn debug_hides_url_and_credentials() {
        let config = RpcConfig::new(
            Network::Regtest,
            "https://node.example/secret-key".to_string(),
            "secret-user".to_string(),
            "secret-pass".to_string(),
            "wallet".to_string(),
        );
        assert_eq!(
            config.url.expose_secret(),
            "https://node.example/secret-key"
        );
        assert!(!format!("{config:?}").contains("secret"));
    }

    #[test]
    fn test_mask_url_secrets() {
        // Test URL with hex secret
        let url_with_secret = "http://user:7822107bcd2054574934586c276a46f0d3eca5e2@localhost:8332";
        let masked = mask_url_secrets(url_with_secret);
        assert!(masked.contains("****************************************"));
        assert!(!masked.contains("7822107bcd2054574934586c276a46f0d3eca5e2"));

        // Test normal URL without secrets
        let normal_url = "http://localhost:8332/wallet/test";
        let masked_normal = mask_url_secrets(normal_url);
        assert_eq!(masked_normal, normal_url);

        // Test URL with query parameter secret
        let url_with_query_secret =
            "http://localhost:8332?token=abc123def456789012345678901234567890abcd";
        let masked_query = mask_url_secrets(url_with_query_secret);
        assert!(!masked_query.contains("abc123def456789012345678901234567890abcd"));
        assert!(masked_query.contains("*"));
    }

    #[test]
    fn test_is_potential_secret() {
        // Test hex secret (like the example in the prompt)
        assert!(is_potential_secret(
            "7822107bcd2054574934586c276a46f0d3eca5e2"
        ));

        // Test base64-like secret
        assert!(is_potential_secret(
            "YWJjMTIzZGVmNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw"
        ));

        // Test normal words/components
        assert!(!is_potential_secret("localhost"));
        assert!(!is_potential_secret("bitcoin"));
        assert!(!is_potential_secret("wallet"));
        assert!(!is_potential_secret("8332"));
        assert!(!is_potential_secret("test"));

        // Test short strings
        assert!(!is_potential_secret("abc123"));
    }
}
