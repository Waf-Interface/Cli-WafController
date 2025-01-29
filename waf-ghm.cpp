#include "waf-ghm.h"
#include <iostream>
#include <fstream>
#include <ctime>

static WafGhm* waf = nullptr;

bool initialize() {
    if (!waf) {
        waf = new WafGhm();
    }
    return waf->initialize();
}

bool loadRule(const char* rule) {
    return waf->loadRule(rule);
}

bool authenticate(const char* username, const char* password) {
    return waf->authenticate(username, password);
}

void shutdown() {
    if (waf) {
        waf->shutdown();
        delete waf;
        waf = nullptr;
    }
}

bool setModSecurityPower(bool enable) {
    return waf->setModSecurityPower(enable);
}

bool logUserAccess(const char* username) {
    return waf->logUserAccess(username);
}

bool showLogs() {
    return waf->showLogs();
}

bool toggleProtectionForHost(const char* host, bool enable) {
    return waf->toggleProtectionForHost(host, enable);
}

// WafGhm class methods
WafGhm::WafGhm() : modsec(nullptr), rules(nullptr), modSecurityEnabled(true) {}

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
    modsec = new modsecurity::ModSecurity();
    rules = new modsecurity::RulesSet();
    return true;
}

bool WafGhm::loadRule(const std::string& rule) {
    if (rules->load(rule.c_str()) < 0) {
        std::cerr << "Failed to load rule: " << (rules->m_parserError.str().empty() ? "Unknown error" : rules->m_parserError.str()) << std::endl;
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

bool WafGhm::setModSecurityPower(bool enable) {
    modSecurityEnabled = enable;
    return true;
}

bool WafGhm::logUserAccess(const std::string& username) {
    std::ofstream log(logFile, std::ios::app);
    if (!log.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return false;
    }

    time_t now = time(0);
    char* dt = ctime(&now);
    log << "User: " << username << " Accessed at: " << dt << std::endl;
    log.close();
    return true;
}

bool WafGhm::showLogs() {
    std::ifstream log(logFile);
    if (!log.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(log, line)) {
        std::cout << line << std::endl;
    }
    log.close();
    return true;
}

bool WafGhm::toggleProtectionForHost(const std::string& host, bool enable) {
    hostProtectionMap[host] = enable;
    return true;
}

bool WafGhm::isModSecurityEnabled() const {
    return modSecurityEnabled;
}
