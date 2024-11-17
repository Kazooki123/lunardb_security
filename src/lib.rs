mod ffi;

use std::collections::HashSet;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use serde_json;
use validator::{Validate, ValidationError};

// SQL Injection Prevention
pub fn prevent_sql_injection(input: &str) -> bool {
    let dialect = GenericDialect {};
    match Parser::parse_sql(&dialect, input) {
        Ok(_) => true, // Valid SQL, not an injection attempt
        Err(_) => false, // Invalid SQL, potential injection
    }
}

// NoSQL Injection Prevention
pub fn prevent_nosql_injection(input: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(value) => !contains_operator(&value),
        Err(_) => false, // Invalid JSON, potential injection
    }
}

fn contains_operator(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.keys().any(|k| k.starts_with('$')) || map.values().any(contains_operator)
        }
        serde_json::Value::Array(arr) => arr.iter().any(contains_operator),
        _ => false,
    }
}

// Input Sanitization
pub fn sanitize_input(input: &str) -> String {
    html_escape::encode_text(input).to_string()
}

// Prepared Statement Simulation
#[derive(Validate)]
pub struct PreparedStatement {
    #[validate(length(min = 1, max = 1000))]
    query: String,
    params: Vec<String>,
}

impl PreparedStatement {
    pub fn new(query: &str) -> Result<Self, ValidationError> {
        let stmt = PreparedStatement {
            query: query.to_string(),
            params: Vec::new(),
        };
        if let Err(errors) = stmt.validate() {
            return Err(ValidationError::new("validation_error"));
        }
        Ok(stmt)
    }

    pub fn bind_param(&mut self, param: &str) {
        self.params.push(sanitize_input(param));
    }

    pub fn execute(&self) -> String {
        let mut result = self.query.clone();
        for param in &self.params {
            result = result.replacen("?", param, 1);
        }
        result
    }
}

// Rate Limiting
pub struct RateLimiter {
    requests: HashSet<String>,
    max_requests: usize,
}

impl RateLimiter {
    pub fn new(max_requests: usize) -> Self {
        RateLimiter {
            requests: HashSet::new(),
            max_requests,
        }
    }

    pub fn check_rate_limit(&mut self, ip_address: &str) -> bool {
        if self.requests.len() >= self.max_requests {
            false
        } else {
            self.requests.insert(ip_address.to_string());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_prevention() {
        assert!(prevent_sql_injection("SELECT * FROM users"));
        assert!(!prevent_sql_injection("SELECT * FROM users; DROP TABLE users;"));
    }

    #[test]
    fn test_nosql_injection_prevention() {
        assert!(prevent_nosql_injection(r#"{"name": "John"}"#));
        assert!(!prevent_nosql_injection(r#"{"$where": "this.password == 'password'"}"#));
    }

    #[test]
    fn test_prepared_statement() {
        let mut stmt = PreparedStatement::new("SELECT * FROM users WHERE id = ?").unwrap();
        stmt.bind_param("1");
        assert_eq!(stmt.execute(), "SELECT * FROM users WHERE id = 1");
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.check_rate_limit("192.168.1.1"));
        assert!(limiter.check_rate_limit("192.168.1.2"));
        assert!(!limiter.check_rate_limit("192.168.1.3"));
    }
}