use libc::{c_char, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use crate::{prevent_sql_injection, prevent_nosql_injection, RateLimiter, PreparedStatement, sanitize_input};

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
    if !prevent_sql_injection(c_str) {
        return false;
    }

    // Check for dangerous NoSQL patterns
    if !prevent_nosql_injection(c_str) {
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

#[no_mangle]
pub extern "C" fn prevent_sql_injection(input: *const c_char) -> bool {
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = c_str.to_str().unwrap_or("");
    crate::prevent_sql_injection(input_str)
}

#[no_mangle]
pub extern "C" fn prevent_nosql_injection(input: *const c_char) -> bool {
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = c_str.to_str().unwrap_or("");
    crate::prevent_nosql_injection(input_str)
}

#[no_mangle]
pub extern "C" fn rate_limiter_new(max_requests: size_t) -> *mut RateLimiter {
    let limiter = Box::new(RateLimiter::new(max_requests));
    Box::into_raw(limiter)
}

#[no_mangle]
pub extern "C" fn check_rate_limit(limiter: *mut RateLimiter, ip_address: *const c_char) -> bool {
    let limiter = unsafe { &mut *limiter };
    let c_str = unsafe { CStr::from_ptr(ip_address) };
    let ip_str = c_str.to_str().unwrap_or("");
    limiter.check_rate_limit(ip_str)
}

#[no_mangle]
pub extern "C" fn rate_limiter_free(limiter: *mut RateLimiter) {
    unsafe {
        Box::from_raw(limiter);
    }
}

#[no_mangle]
pub extern "C" fn prepared_statement_new(query: *const c_char) -> *mut PreparedStatement {
    let c_str = unsafe { CStr::from_ptr(query) };
    let query_str = c_str.to_str().unwrap_or("");
    match PreparedStatement::new(query_str) {
        Ok(stmt) => Box::into_raw(Box::new(stmt)),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn bind_param(stmt: *mut PreparedStatement, param: *const c_char) {
    let stmt = unsafe { &mut *stmt };
    let c_str = unsafe { CStr::from_ptr(param) };
    let param_str = c_str.to_str().unwrap_or("");
    stmt.bind_param(param_str);
}

#[no_mangle]
pub extern "C" fn execute(stmt: *const PreparedStatement) -> *mut c_char {
    let stmt = unsafe { &*stmt };
    let result = stmt.execute();
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn prepared_statement_free(stmt: *mut PreparedStatement) {
    unsafe {
        Box::from_raw(stmt);
    }
}

#[no_mangle]
pub extern "C" fn sanitize_input(input: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = c_str.to_str().unwrap_or("");
    let sanitized = crate::sanitize_input(input_str);
    CString::new(sanitized).unwrap().into_raw()
}