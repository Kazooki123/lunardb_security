mod ffi;

use regex::Regex;
use std::collections::HashSet;

// SQL Injection Prevention
pub fn prevent_sql_injection(input: &str) -> bool {
    // Basic check for common SQL injection patterns
    let sql_patterns = Regex::new(r"(?i)((\s*([-+*/()]|'\s*'|'&'|'|'|'<'|'>'|'='|'<='|'>='|'<>'|'!='|'<=>'|'!<'|'!>'|'!<='|'!>='|'!<>'|'!='|'!<=>'|'!<'|'!>'|'!<='|'!>='|'!<>'|'!=')?\s*){1,})(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bUNION\b|\bALTER\b|\bCREATE\b|\bTABLE\b|\bFROM\b|\bWHERE\b|\bAND\b|\bOR\b)").unwrap();
    !sql_patterns.is_match(input)
}

// NoSQL Injection Prevention
pub fn prevent_nosql_injection(input: &str) -> bool {
    // Check for NoSQL injection patterns (e.g., MongoDB)
    let nosql_patterns = Regex::new(r"(\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$or|\$and)").unwrap();
    !nosql_patterns.is_match(input)
}

// Input Sanitization
pub fn sanitize_input(input: &str) -> String {
    // Remove or escape potentially dangerous characters
    input.replace(['<', '>', '&', '"', '\''], "")
}

// Prepared Statement Simulation
pub struct PreparedStatement {
    query: String,
    params: Vec<String>,
}

impl PreparedStatement {
    pub fn new(query: &str) -> Self {
        PreparedStatement {
            query: query.to_string(),
            params: Vec::new(),
        }
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
        assert!(prevent_nosql_injection("name: 'John'"));
        assert!(!prevent_nosql_injection("name: {$ne: null}"));
    }

    // More test coming later on...
}