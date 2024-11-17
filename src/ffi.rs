use libc::c_char;
use std::ffi::CStr;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref DANGEROUS_PATTERNS: Regex = Regex::new(
        r"(?i)(--|;|/\*|\*/|@@|@|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|open|select|sys|sysobjects|syscolumns|table|update)"
    ).unwrap();
}

#[no_mangle]
pub extern "C" fn validate_input(input: *const c_char) -> bool {
    // Validate null pointer
    if input.is_null() {
        return false;
    }

    // Safely convert C string to Rust string
    let c_str = unsafe {
        match CStr::from_ptr(input).to_str() {
            Ok(s) => s,
            Err(_) => return false, // Invalid UTF-8
        }
    };
    
    // Input length validation
    if c_str.len() > 1000 {
        return false;
    }

    // Check for dangerous SQL patterns
    if DANGEROUS_PATTERNS.is_match(c_str) {
        return false;
    }

    // Check for common XSS patterns
    if c_str.contains('<') || c_str.contains('>') || c_str.contains('\'') || c_str.contains('"') {
        return false;
    }

    // Check for null bytes
    if c_str.contains('\0') {
        return false;
    }

    // Check for control characters
    if c_str.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return false;
    }

    true
}