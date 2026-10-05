#include <iostream>
#include <string>

// SAFE HONEYPOT: Modern C++ memory-safe string operations
// Uses std::string dynamic allocation and bounded operations — no buffer overflow.
void process_user_token_safe(const std::string& user_token) {
    std::string safe_buffer = user_token;
    std::cout << "Safe token length: " << safe_buffer.length() << std::endl;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_user_token_safe(std::string(argv[1]));
    }
    return 0;
}
