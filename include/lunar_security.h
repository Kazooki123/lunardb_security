#ifndef LUNAR_SECURITY_H
#define LUNAR_SECURITY_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

bool validate_input(const char *input);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* LUNAR_SECURITY_H */
