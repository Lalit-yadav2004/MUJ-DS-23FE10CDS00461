#include <iostream>
#include <cstring>

// VULNERABLE: Classic Stack-based Buffer Overflow (CWE-120 / CWE-121)
// User-supplied input is copied directly into a fixed-size 64-byte buffer without bounds checking.
void process_user_token(const char* user_token) {
    char local_buffer[64];
    strcpy(local_buffer, user_token);
    std::cout << "Token processed: " << local_buffer << std::endl;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_user_token(argv[1]);
    }
    return 0;
}
