#include "waf-ghm.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <string>
#include <dirent.h>
#include <chrono>
#include <ctime>
#include <sstream>

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
        std::cerr << "Failed to load rule: " << rules->m_parserError.str() << std::endl;
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

//-------Section for changing the modsec power------------------------------------------------
/* The libmodsec unformaly doesnt support the changing power so we just for now turning off the engine manually.*/

// Update the nginx.conf
bool updateNginxConfig(bool enable) {
    const std::string nginxConfigPath = "/etc/nginx/nginx.conf";
    std::ifstream nginxConfigFile(nginxConfigPath);
    std::string line;
    std::string tempFilePath = "/tmp/nginx.conf.temp";
    std::ofstream tempFile(tempFilePath);

    if (!nginxConfigFile.is_open() || !tempFile.is_open()) {
        std::cerr << "Failed to open nginx config file for writing." << std::endl;
        return false;
    }

    bool modSecurityFound = false;

    while (std::getline(nginxConfigFile, line)) {
        if (line.find("modsecurity") != std::string::npos) {
            modSecurityFound = true;
            if (enable) {
                line = "modsecurity on;";
            } else {
                line = "modsecurity off;";
            }
        }
        tempFile << line << std::endl;
    }

    if (!modSecurityFound) {
        if (enable) {
            tempFile << "modsecurity on;" << std::endl;
        } else {
            tempFile << "modsecurity off;" << std::endl;
        }
    }

    nginxConfigFile.close();
    tempFile.close();

    if (rename(tempFilePath.c_str(), nginxConfigPath.c_str()) != 0) {
        std::cerr << "Failed to update nginx config file." << std::endl;
        return false;
    }

    return true;
}

// Update modsecurity.conf
bool updateModSecurityConfig(bool enable) {
    const std::string modsecConfigPath = "/etc/nginx/modsecurity.conf";
    std::ifstream modsecConfigFile(modsecConfigPath);
    std::string line;
    std::string tempFilePath = "/tmp/modsecurity.conf.temp";
    std::ofstream tempFile(tempFilePath);

    if (!modsecConfigFile.is_open() || !tempFile.is_open()) {
        std::cerr << "Failed to open modsecurity config file for reading or writing." << std::endl;
        return false;
    }

    bool configUpdated = false;
    while (std::getline(modsecConfigFile, line)) {
        if (line.find("SecRuleEngine") != std::string::npos) {
            std::string newLine = (enable) ? "SecRuleEngine On" : "SecRuleEngine Off";
            if (line != newLine) { 
                line = newLine;
                configUpdated = true;
            }
        }
        tempFile << line << std::endl;
    }

    modsecConfigFile.close();
    tempFile.close();

    if (configUpdated && rename(tempFilePath.c_str(), modsecConfigPath.c_str()) != 0) {
        std::cerr << "Failed to update modsecurity config file." << std::endl;
        return false;
    }
    std::remove(tempFilePath.c_str());

    return configUpdated;
}

bool WafGhm::setModSecurityPower(bool enable) {
    if (modsec) {
        if (!updateNginxConfig(enable) || !updateModSecurityConfig(enable)) {
            std::cerr << "Failed to update ModSecurity configuration files." << std::endl;
            return false;
        }
        
        std::string reloadCmd = "sudo systemctl reload nginx";
        int result = system(reloadCmd.c_str());
        
        if (result != 0) {
            std::cerr << "Failed to reload Nginx. Exit code: " << result << std::endl;
            return false;
        }
        
        std::cout << (enable ? "Enabling" : "Disabling") << " ModSecurity..." << std::endl;
        modSecurityEnabled = enable;
        return true;
    } else {
        std::cerr << "ModSecurity is not initialized." << std::endl;
        return false;
    }
}

//-----Section for logs--------------------------------------

bool WafGhm::logUserAccess(const std::string& username) {
    std::ofstream log(logFile, std::ios::app);
    if (!log.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return false;
    }
    
    time_t now = time(0);
    char* dt = ctime(&now);  // Get current date and time
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



//--------------------------Checking status of waf--------------------------------------------
bool checkModSecurityInNginxConf(){
    const std::string nginxConfigPath = "/etc/nginx/nginx.conf";
    
    std::ifstream nginxConfigFile(nginxConfigPath);
    if (!nginxConfigFile.is_open()) {
        std::cerr << "NGINX config file not found: " << nginxConfigPath << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(nginxConfigFile, line)) {
        if (line.find("modsec") != std::string::npos || line.find("ModSecurity") != std::string::npos) {
            std::cout << "ModSecurity is included in the NGINX configuration." << std::endl;
            return true;
        }
    }
    
    std::cout << "ModSecurity is NOT included in the NGINX configuration." << std::endl;
    return false;
}

bool checkModSecurityConf()  {
    const std::string modsecConfigPath = "/etc/nginx/modsecurity.conf";
    std::ifstream modsecConfigFile(modsecConfigPath);
    if (!modsecConfigFile.is_open()) {
        std::cerr << "ModSecurity config file not found: " << modsecConfigPath << std::endl;
        return false;
    }

    std::string line;
    bool isSecRuleEngineFound = false;
    while (std::getline(modsecConfigFile, line)) {
        // Check if the SecRuleEngine is mentioned
        if (line.find("SecRuleEngine") != std::string::npos) {
            isSecRuleEngineFound = true;
            // Check if SecRuleEngine is "On"
            if (line.find("On") != std::string::npos) {
                std::cout << "ModSecurity is enabled." << std::endl;
                return true;
            } else if (line.find("DetectionOnly") != std::string::npos) {
                std::cout << "ModSecurity is in detection-only mode." << std::endl;
                return false;
            }
        }
    }

    if (!isSecRuleEngineFound) {
        std::cout << "SecRuleEngine setting not found in ModSecurity config." << std::endl;
        return false;
    }
    
    return false;
}

bool WafGhm::updateModSecEngineInNginxConfig(bool enable) {
    const std::string nginxConfigPath = "/usr/local/nginx/conf/nginx.conf";
    std::ifstream nginxConfigFile(nginxConfigPath);
    std::string line;
    std::string tempFilePath = "/tmp/nginx.conf.temp";
    std::ofstream tempFile(tempFilePath);

    if (!nginxConfigFile.is_open() || !tempFile.is_open()) {
        std::cerr << "Failed to open Nginx config file for reading or writing." << std::endl;
        return false;
    }

    bool modSecurityFound = false;

    while (std::getline(nginxConfigFile, line)) {
        if (line.find("modsecurity") != std::string::npos) {
            modSecurityFound = true;
            if (enable) {
                line = "modsecurity on;";
            } else {
                line = "modsecurity off;";
            }
        }
        tempFile << line << std::endl;
    }

    if (!modSecurityFound) {
        if (enable) {
            tempFile << "modsecurity on;" << std::endl;
        } else {
            tempFile << "modsecurity off;" << std::endl;
        }
    }

    nginxConfigFile.close();
    tempFile.close();

    if (rename(tempFilePath.c_str(), nginxConfigPath.c_str()) != 0) {
        std::cerr << "Failed to update Nginx config file." << std::endl;
        return false;
    }

    return true;
}

bool WafGhm::showAuditLogs() {
    const std::string logFilePath = "/var/log/modsec_audit.log";
    std::ifstream logFile(logFilePath);

    if (!logFile.is_open()) {
        std::cerr << "Failed to open ModSecurity audit log file." << std::endl;
        return false;
    }

    // Get current time minus 30 minutes
    auto now = std::chrono::system_clock::now();
    auto cutoffTime = now - std::chrono::minutes(30);
    std::time_t cutoffTimeT = std::chrono::system_clock::to_time_t(cutoffTime);
    std::string cutoffStr = std::ctime(&cutoffTimeT);

    std::string line;
    while (std::getline(logFile, line)) {
        if (line.find(cutoffStr) != std::string::npos) {
            std::cout << line << std::endl;
        }
    }
    logFile.close();
    return true;
}

bool WafGhm::clearAuditLogs() {
    const std::string logFilePath = "/var/log/modsec_audit.log";
    std::string command = "sudo truncate -s 0 " + logFilePath;
    int result = system(command.c_str());

    if (result != 0) {
        std::cerr << "Failed to clear ModSecurity audit logs." << std::endl;
        return false;
    }

    std::cout << "Audit logs cleared successfully." << std::endl;
    return true;
}

bool WafGhm::showModSecRules() {
    const std::string rulesDir = "/usr/local/nginx/rules";
    DIR* dir = opendir(rulesDir.c_str());

    if (!dir) {
        std::cerr << "Failed to open rules directory." << std::endl;
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;
        if (filename.find(".conf") != std::string::npos) {
            std::cout << filename << std::endl;
        }
    }

    closedir(dir);
    return true;
}
WAF_GHM_API bool isModSecurityEnabled()  {
    bool isModSecurityIncluded = checkModSecurityInNginxConf();
    bool isModSecurityEnabledInConfig = checkModSecurityConf();
    return isModSecurityIncluded && isModSecurityEnabledInConfig;
}
