#include <stdio.h>
#include <stdlib.h>

// VULNERABLE: Uncontrolled Format String (CWE-134)
// User input is passed directly as the format string argument to printf().
void log_client_message(const char* client_msg) {
    printf(client_msg);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc > 1) {
        log_client_message(argv[1]);
    }
    return 0;
}
