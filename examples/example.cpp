#include <iostream>
#include "lunar_security.h"

int main() {
    const char* safe_input = "SELECT * FROM users";
    const char* unsafe_input = "SELECT * FROM users; DROP TABLE users;";

    std::cout << "Safe input is " << (validate_input(safe_input) ? "valid" : "invalid") << std::endl;
    std::cout << "Unsafe input is " << (validate_input(unsafe_input) ? "valid" : "invalid") << std::endl;

    return 0;
}
