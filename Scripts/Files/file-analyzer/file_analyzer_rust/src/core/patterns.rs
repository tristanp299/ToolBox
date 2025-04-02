/// Pattern definitions for the file analyzer
///
/// This module contains definitions of regex patterns used to detect different
/// types of data in files, including sensitive information, API endpoints,
/// network information, etc.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use base64::Engine;

/// Load all pattern categories
pub fn load_patterns() -> HashMap<String, HashMap<String, String>> {
    let mut all_patterns = HashMap::new();
    
    // Add basic patterns
    all_patterns.insert("general".to_string(), get_patterns());
    all_patterns.insert("hash".to_string(), get_hash_patterns());
    
    // Convert nested patterns to flat patterns for compatibility
    let language_patterns = get_language_security_patterns();
    for (language, patterns) in language_patterns {
        let lang_prefix = format!("lang_{}", language);
        for (pattern_name, pattern) in patterns {
            let key = format!("{}_{}", lang_prefix, pattern_name);
            all_patterns.get_mut("general").unwrap().insert(key, pattern);
        }
    }
    
    let network_patterns = get_network_patterns();
    for (network_category, patterns) in network_patterns {
        let category_prefix = format!("net_{}", network_category);
        for (pattern_name, pattern) in patterns {
            let key = format!("{}_{}", category_prefix, pattern_name);
            all_patterns.get_mut("general").unwrap().insert(key, pattern);
        }
    }
    
    // Add the rest of the patterns
    all_patterns.get_mut("general").unwrap().extend(get_software_version_patterns());
    all_patterns.get_mut("general").unwrap().extend(get_package_file_patterns());
    
    all_patterns
}

/// Get regular expressions for different types of data.
pub fn get_patterns() -> HashMap<String, String> {
    let mut patterns = HashMap::new();
    
    // IP addresses and network identifiers
    patterns.insert("ipv4".to_string(), r"\b(?:\d{1,3}\.){3}\d{1,3}\b".to_string());
    patterns.insert("ipv6".to_string(), r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b".to_string());
    patterns.insert("email".to_string(), r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string());
    patterns.insert("domain_keywords".to_string(), r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b".to_string());
    patterns.insert("url".to_string(), r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)".to_string());
    
    // Hash and encoded data patterns
    patterns.insert("hash".to_string(), r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}|\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})\b".to_string());
    patterns.insert("base64_encoded".to_string(), r"[A-Za-z0-9+/=]{40,}".to_string());
    
    // API and authentication patterns
    patterns.insert("api_key".to_string(), r#"(?i)(?:api[_-]?key|secret)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("jwt".to_string(), r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*".to_string());
    
    // Credentials and sensitive information
    patterns.insert("username".to_string(), r#"(?i)(?:username|user|login)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("password".to_string(), r#"(?i)(?:password|pass|pwd)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("private_key".to_string(), r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----".to_string());
    patterns.insert("public_key".to_string(), r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PUBLIC KEY-----".to_string());
    patterns.insert("aws_key".to_string(), r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}".to_string());
    patterns.insert("credit_card".to_string(), r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".to_string());
    patterns.insert("social_security".to_string(), r"\b\d{3}-\d{2}-\d{4}\b".to_string());
    
    // Database and connection strings
    patterns.insert("database_connection".to_string(), r"(?i)(?:mysql|postgresql|mongodb|sqlserver)://[^:\s]+:[^@\s]+@[^:\s]+:\d+".to_string());
    
    // Authentication tokens
    patterns.insert("access_token".to_string(), r#"(?i)(?:access[_-]?token|bearer[_-]?token)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("refresh_token".to_string(), r#"(?i)(?:refresh[_-]?token)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("oauth_token".to_string(), r#"(?i)(?:oauth[_-]?token)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("session_id".to_string(), r#"(?i)(?:session[_-]?id|sid)[=:]\s*["'][^"']+["']"#.to_string());
    patterns.insert("cookie".to_string(), r#"(?i)(?:cookie|session)[=:]\s*["'][^"']+["']"#.to_string());
    
    // API-related patterns
    patterns.insert("api_endpoint".to_string(), r#"(?i)(?:https?://[^/\s]+)?/(?:api|rest|graphql|v\d+)/[^\s"']+#"#.to_string());
    patterns.insert("api_method".to_string(), r#"(?i)(?:["']|\b)(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)(?:["']|\b)"#.to_string());
    patterns.insert("content_type".to_string(), r#"(?i)(?:Content-Type|content-type)[=:]\s*["']([^"']+)["']"#.to_string());
    patterns.insert("api_version".to_string(), r#"(?i)(?:v\d+(?:\.\d+)*|\bversion[=:]\s*["']([^"']+)["'])"#.to_string());
    patterns.insert("api_parameter".to_string(), r"(?i)(?:[?&][^=\s]+=[^&\s]+)".to_string());
    patterns.insert("authorization_header".to_string(), r#"(?i)(?:Authorization|auth)[=:]\s*["']([^"']+)["']"#.to_string());
    patterns.insert("rate_limit".to_string(), r#"(?i)(?:rate[_-]?limit|x-rate-limit)[=:]\s*["']?(\d+)["']?"#.to_string());
    patterns.insert("api_key_param".to_string(), r"(?i)(?:api_key|apikey|key)=([^&\s]+)".to_string());
    
    // HTTP and API patterns
    patterns.insert("curl_command".to_string(), r#"(?i)curl\s+(?:-X\s+(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+)?["']?https?://[^\s"'>]+"#.to_string());
    patterns.insert("webhook_url".to_string(), r#"(?i)(?:webhook|callback)[=:]\s*["']?https?://[^\s"']+["']?"#.to_string());
    patterns.insert("http_status_code".to_string(), r#"(?i)(?:status|code)[=:]\s*["']?(\d{3})["']?"#.to_string());
    
    // API specification patterns
    patterns.insert("openapi_schema".to_string(), r#"(?i)(?:"openapi"\s*:\s*"[^"]*)"#.to_string());
    patterns.insert("graphql_query".to_string(), r"(?i)(?:query\s+\w+\s*\{[^}]*\}|mutation\s+\w+\s*\{[^}]*\})".to_string());
    patterns.insert("graphql_schema".to_string(), r"(?i)(?:type\s+\w+\s*\{[^}]*\}|input\s+\w+\s*\{[^}]*\}|interface\s+\w+\s*\{[^}]*\})".to_string());
    patterns.insert("rest_resource".to_string(), r"(?i)(?:\/[a-zA-Z0-9_-]+(?:\/\{[a-zA-Z0-9_-]+\})?(?:\/[a-zA-Z0-9_-]+)*)".to_string());
    
    // API response patterns
    patterns.insert("xml_response".to_string(), r"(?i)(?:<\?xml[^>]+>|<[a-zA-Z0-9_:]+\s+xmlns)".to_string());
    patterns.insert("error_pattern".to_string(), r#"(?i)(?:"error"\s*:\s*\{|"errors"\s*:\s*\[|\<e>|\<errors>)"#.to_string());
    patterns.insert("http_error".to_string(), r"(?i)(?:[45]\d{2}\s+[A-Za-z\s]+)".to_string());
    
    // API authentication schemes
    patterns.insert("oauth_flow".to_string(), r"(?i)(?:oauth2|authorization_code|client_credentials|password|implicit)".to_string());
    patterns.insert("api_auth_scheme".to_string(), r"(?i)(?:bearer|basic|digest|apikey|oauth|jwt)\s+auth".to_string());
    
    patterns
}

/// Get patterns for hash identification.
pub fn get_hash_patterns() -> HashMap<String, String> {
    let mut patterns = HashMap::new();
    
    patterns.insert("MD5".to_string(), r"^[a-fA-F0-9]{32}$".to_string());
    patterns.insert("SHA-1".to_string(), r"^[a-fA-F0-9]{40}$".to_string());
    patterns.insert("SHA-256".to_string(), r"^[a-fA-F0-9]{64}$".to_string());
    patterns.insert("SHA-512".to_string(), r"^[a-fA-F0-9]{128}$".to_string());
    patterns.insert("NTLM".to_string(), r"^[a-fA-F0-9]{32}$".to_string());
    patterns.insert("MySQL4".to_string(), r"^[a-fA-F0-9]{16}$".to_string());
    patterns.insert("MySQL5".to_string(), r"^[a-fA-F0-9]{40}$".to_string());
    patterns.insert("BCrypt".to_string(), r"^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$".to_string());
    patterns.insert("RIPEMD-160".to_string(), r"^[a-fA-F0-9]{40}$".to_string());
    
    patterns
}

/// Get language-specific security pattern detection.
pub fn get_language_security_patterns() -> HashMap<String, HashMap<String, String>> {
    let mut language_patterns = HashMap::new();
    
    // Python patterns
    let mut python = HashMap::new();
    python.insert("Hardcoded Secret".to_string(), r#"(?:password|secret|key|token)\s*=\s*["'][^"']+["']"#.to_string());
    python.insert("Shell Injection".to_string(), r"(?:os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(".to_string());
    python.insert("SQL Injection".to_string(), r#"(?:execute|executemany)\s*\(\s*[f"']"#.to_string());
    python.insert("Pickle Usage".to_string(), r"pickle\.(?:load|loads)".to_string());
    python.insert("Temp File".to_string(), r#"(?:tempfile\.mk(?:stemp|temp)|open\s*\(\s*["']\/tmp\/)"#.to_string());
    python.insert("Assert Usage".to_string(), r"\bassert\b".to_string());
    python.insert("HTTP Without TLS".to_string(), r"http:\/\/(?!localhost|127\.0\.0\.1)".to_string());
    language_patterns.insert("python".to_string(), python);
    
    // JavaScript patterns
    let mut javascript = HashMap::new();
    javascript.insert("Eval Usage".to_string(), r"\beval\s*\(".to_string());
    javascript.insert("Document Write".to_string(), r"document\.write\s*\(".to_string());
    javascript.insert("innerHtml Assignment".to_string(), r"\.innerHTML\s*=".to_string());
    javascript.insert("DOM-based XSS".to_string(), r"(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer))".to_string());
    javascript.insert("DOM Storage Usage".to_string(), r"(?:localStorage|sessionStorage)\.".to_string());
    javascript.insert("Hardcoded JWT".to_string(), r#"["']eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*["']"#.to_string());
    javascript.insert("Protocol-relative URL".to_string(), r#"["']\/\/\w+"#.to_string());
    javascript.insert("HTTP Without TLS".to_string(), r"http:\/\/(?!localhost|127\.0\.0\.1)".to_string());
    javascript.insert("Dangerous Function Creation".to_string(), r#"(?:new\s+Function|setTimeout\s*\(\s*["'`][^"'`]*["'`]\s*\)|setInterval\s*\(\s*["'`][^"'`]*["'`]\s*\))"#.to_string());
    language_patterns.insert("javascript".to_string(), javascript);
    
    // Java patterns
    let mut java = HashMap::new();
    java.insert("Hardcoded Password".to_string(), r#"(?:password|pwd|passwd)\s*=\s*["'][^"']+["']"#.to_string());
    java.insert("SQL Injection".to_string(), r#"(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*["'].*\+"#.to_string());
    java.insert("Command Injection".to_string(), r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)".to_string());
    java.insert("XXE Vulnerability".to_string(), r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)".to_string());
    java.insert("Crypto Issues".to_string(), r"(?:MD5|DES|AES/ECB)".to_string());
    java.insert("Random Predictable".to_string(), r"new\s+Random\s*\(\s*\)".to_string());
    java.insert("Trust All Certificates".to_string(), r"TrustAllCerts|X509TrustManager".to_string());
    language_patterns.insert("java".to_string(), java);
    
    language_patterns
}

/// Get network protocol and security patterns.
pub fn get_network_patterns() -> HashMap<String, HashMap<String, String>> {
    let mut network_patterns = HashMap::new();
    
    // Protocol patterns
    let mut protocols = HashMap::new();
    protocols.insert("HTTP".to_string(), r"(?i)(?:http\.(?:get|post|put|delete)|fetch\(|XMLHttpRequest|axios)".to_string());
    protocols.insert("HTTPS".to_string(), r"(?i)https:\/\/".to_string());
    protocols.insert("FTP".to_string(), r"(?i)(?:ftp:\/\/|ftps:\/\/|\bftp\s+(?:open|get|put))".to_string());
    protocols.insert("SSH".to_string(), r"(?i)(?:ssh\s+|ssh2_connect|new\s+SSH|JSch)".to_string());
    protocols.insert("SMTP".to_string(), r"(?i)(?:smtp\s+|mail\s+send|createTransport|sendmail|new\s+SmtpClient)".to_string());
    protocols.insert("DNS".to_string(), r"(?i)(?:dns\s+lookup|resolv|nslookup|dig\s+)".to_string());
    protocols.insert("WebSocket".to_string(), r"(?i)(?:new\s+WebSocket|createWebSocketClient|websocket\.connect)".to_string());
    protocols.insert("GraphQL".to_string(), r"(?i)(?:graphql\s+|ApolloClient|gql`)".to_string());
    protocols.insert("TCP/IP".to_string(), r"(?i)(?:socket\.|Socket\(|createServer|listen\(\d+|bind\(\d+|connect\(\d+)".to_string());
    network_patterns.insert("protocols".to_string(), protocols);
    
    // Security issues
    let mut security_issues = HashMap::new();
    security_issues.insert("Clear Text Credentials".to_string(), r"(?i)(?:auth=|user:pass@|username=\w+&password=)".to_string());
    security_issues.insert("Insecure Protocol".to_string(), r"(?i)(?:ftp:\/\/|telnet:\/\/|http:\/\/(?!localhost|127\.0\.0\.1))".to_string());
    security_issues.insert("Hardcoded IP".to_string(), r#"\b(?:PUBLIC_IP|SERVER_ADDR|API_HOST)\s*=\s*["'](?:\d{1,3}\.){3}\d{1,3}["']"#.to_string());
    security_issues.insert("Open Port".to_string(), r#"(?i)(?:listen\(\s*\d+|port\s*=\s*\d+|\.connect\(\s*(?:["']\w+["']\s*,\s*)?\d+\))"#.to_string());
    security_issues.insert("Weak TLS".to_string(), r"(?i)(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|\bRC4\b|\bDES\b|MD5WithRSA|allowAllHostnames)".to_string());
    security_issues.insert("Certificate Validation Disabled".to_string(), r"(?i)(?:verify=False|CERT_NONE|InsecureRequestWarning|rejectUnauthorized:\s*false|trustAllCerts)".to_string());
    network_patterns.insert("security_issues".to_string(), security_issues);
    
    // Configuration
    let mut configuration = HashMap::new();
    configuration.insert("port".to_string(), r#"(?:^|\s)(?:PORT|port)\s*(?:=|:)\s*(\d+)"#.to_string());
    configuration.insert("host".to_string(), r#"(?:^|\s)(?:HOST|host|SERVER|server)\s*(?:=|:)\s*["']([\w\.\-]+)["']"#.to_string());
    network_patterns.insert("configuration".to_string(), configuration);
    
    network_patterns
}

/// Get patterns to detect software versions.
pub fn get_software_version_patterns() -> HashMap<String, String> {
    let mut patterns = HashMap::new();
    
    patterns.insert("jquery".to_string(), r"(?:jquery[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("bootstrap".to_string(), r"(?:bootstrap[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("react".to_string(), r"(?:react[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("vue".to_string(), r"(?:vue[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("angular".to_string(), r"(?:angular[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("lodash".to_string(), r"(?:lodash[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("express".to_string(), r"(?:express[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("django".to_string(), r"(?:django[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("flask".to_string(), r"(?:flask[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("spring".to_string(), r"(?:spring[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("tensorflow".to_string(), r"(?:tensorflow[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("pytorch".to_string(), r"(?:pytorch[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("openssl".to_string(), r"(?:openssl[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)".to_string());
    patterns.insert("nginx".to_string(), r"(?:nginx[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("apache".to_string(), r"(?:apache[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("php".to_string(), r"(?:php[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("node.js".to_string(), r"(?:node[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("python".to_string(), r"(?:python[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("java".to_string(), r"(?:java[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("dotnet".to_string(), r"(?:\.net[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    
    patterns
}

/// Get patterns to detect versions in dependency files.
pub fn get_package_file_patterns() -> HashMap<String, String> {
    let mut patterns = HashMap::new();
    
    patterns.insert("package.json".to_string(), r#""([\w\-@/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"#.to_string());
    patterns.insert("requirements.txt".to_string(), r"([\w\-]+)(?:={1,2}|>=|<=|>|<|~=)([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("composer.json".to_string(), r#""([\w\-/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"#.to_string());
    patterns.insert("build.gradle".to_string(), r"([\w\-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string());
    patterns.insert("pom.xml".to_string(), r"<([\w\-\.]+)>[0-9]+\.[0-9]+(?:\.[0-9]+)?</\1>".to_string());
    
    patterns
}

/// Helper function to compile pattern
pub fn compile_pattern(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            log::error!("Error compiling pattern: {}", e);
            None
        }
    }
}

/// Precompile commonly used patterns for efficiency
pub fn precompile_patterns() -> HashMap<String, Regex> {
    let patterns = get_patterns();
    let mut compiled = HashMap::new();
    
    for (name, pattern) in patterns {
        if let Some(regex) = compile_pattern(&pattern) {
            compiled.insert(name, regex);
        }
    }
    
    compiled
}

lazy_static! {
    /// Precompiled patterns available globally
    pub static ref COMPILED_PATTERNS: HashMap<String, Regex> = precompile_patterns();
}

/// Validate if a string is a valid IPv4 address
pub fn is_valid_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    
    if parts.len() != 4 {
        return false;
    }
    
    for part in parts {
        if let Ok(_) = part.parse::<u8>() {
            // Valid octet
        } else {
            return false;
        }
    }
    
    true
}

/// Identify the hash type based on pattern and length
pub fn identify_hash(hash_value: &str) -> String {
    let hash_patterns = get_hash_patterns();
    let hash_value = hash_value.trim();
    
    let mut potential_matches = Vec::new();
    
    // Match against patterns
    for (hash_type, pattern) in &hash_patterns {
        if let Some(regex) = compile_pattern(pattern) {
            if regex.is_match(hash_value) {
                potential_matches.push(hash_type.to_string());
            }
        }
    }
    
    // Additional length-based checks
    match hash_value.len() {
        32 => {
            if !potential_matches.contains(&"MD5".to_string()) {
                potential_matches.push("MD5".to_string());
            }
        },
        40 => {
            if !potential_matches.contains(&"SHA-1".to_string()) {
                potential_matches.push("SHA-1".to_string());
            }
        },
        64 => {
            if !potential_matches.contains(&"SHA-256".to_string()) {
                potential_matches.push("SHA-256".to_string());
            }
        },
        _ => {}
    }
    
    if potential_matches.is_empty() {
        "Unknown".to_string()
    } else {
        potential_matches.join("/")
    }
}

/// Calculate Shannon entropy of a string
pub fn calculate_entropy(string: &str) -> f64 {
    if string.is_empty() {
        return 0.0;
    }
    
    let mut freq_map = HashMap::new();
    let length = string.len() as f64;
    
    for c in string.chars() {
        *freq_map.entry(c).or_insert(0) += 1;
    }
    
    let mut entropy = 0.0;
    for count in freq_map.values() {
        let probability = *count as f64 / length;
        entropy -= probability * probability.log2();
    }
    
    entropy
}

/// Check if a string is likely valid base64
pub fn is_valid_base64(string: &str) -> bool {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    // Base64 strings are typically multiples of 4 in length
    // and should only contain characters from the Base64 charset
    if string.len() % 4 != 0 {
        return false;
    }
    
    for c in string.chars() {
        if !charset.contains(c) {
            return false;
        }
    }
    
    // Try decoding
    match base64::engine::general_purpose::STANDARD.decode(string) {
        Ok(_) => true,
        Err(_) => false,
    }
} 