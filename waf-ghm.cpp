#include "waf-ghm.h"
#include <iostream>

WafGhm::WafGhm() : modsec(nullptr), rules(nullptr) {}

WafGhm::~WafGhm() {
    if (rules) {
        delete rules;
        rules = nullptr;
    }
    if (modsec) {
        delete modsec;
        modsec = nullptr;
    }
}

bool WafGhm::initialize() {
    modsec = new ModSecurity::ModSecurity();
    rules = new ModSecurity::RulesSet();
    return true;
}

bool WafGhm::loadRule(const std::string& rule) {
    if (rules->load(rule) < 0) {
        std::cerr << "Failed to load rule: " << rules->m_parserError << std::endl;
        return false;
    }
    return true;
}


bool WafGhm::authenticate(const std::string& username, const std::string& password) {
    return (username == validUsername && password == validPassword);
}

void WafGhm::shutdown() {
    delete rules;
    rules = nullptr;
    delete modsec;
    modsec = nullptr;
}
