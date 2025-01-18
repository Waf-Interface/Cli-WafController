#include "waf-ghm.h"
#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) {
    
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] << " --username <username> --password <password> --rule <rule>" << std::endl;
        return 1;
    }

    std::string username;
    std::string password;
    std::string rule;

    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (arg == "--username") {
            username = argv[i + 1];
        } else if (arg == "--password") {
            password = argv[i + 1];
        } else if (arg == "--rule") {
            rule = argv[i + 1];
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return 1;
        }
    }

    WafGhm waf;
    if (!waf.initialize()) {
        std::cerr << "Initialization failed." << std::endl;
        return 1;
    }

    if (!waf.authenticate(username, password)) {
        std::cerr << "Authentication failed." << std::endl;
        return 1;
    }

    if (!waf.loadRule(rule)) {
        std::cerr << "Failed to load rule." << std::endl;
        return 1;
    }

    std::cout << "Rule loaded successfully." << std::endl;
    waf.shutdown();
    return 0;
}
