#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

#pragma once

extern "C" {

// Input validation
bool validate_input(const char *input);

// SQL injection prevention
bool prevent_sql_injection(const char *input);

// NoSQL injection prevention 
bool prevent_nosql_injection(const char *input);

// Rate limiting
typedef struct RateLimiter RateLimiter;
RateLimiter* rate_limiter_new(size_t max_requests);
bool check_rate_limit(RateLimiter *limiter, const char *ip_address);
void rate_limiter_free(RateLimiter *limiter);

// Prepared statements
typedef struct PreparedStatement PreparedStatement;
PreparedStatement* prepared_statement_new(const char *query);
void bind_param(PreparedStatement *stmt, const char *param);
char* execute(const PreparedStatement *stmt);
void prepared_statement_free(PreparedStatement *stmt);

// Input sanitization
char* sanitize_input(const char *input);

} // extern "C"
