#ifndef WAF_GHM_H
#define WAF_GHM_H

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <string>
#include <map>

#ifdef _WIN32
    #define WAF_GHM_API __declspec(dllexport)  // Windows specific
#else
    #define WAF_GHM_API __attribute__((visibility("default")))  // Linux specific
#endif

#ifdef __cplusplus
extern "C" {
#endif

WAF_GHM_API bool initialize();
WAF_GHM_API bool loadRule(const char* rule);
WAF_GHM_API bool authenticate(const char* username, const char* password);
WAF_GHM_API void shutdown();
WAF_GHM_API bool setModSecurityPower(bool enable);
WAF_GHM_API bool logUserAccess(const char* username);
WAF_GHM_API bool showLogs();
WAF_GHM_API bool toggleProtectionForHost(const char* host, bool enable);
WAF_GHM_API bool isModSecurityEnabled();
WAF_GHM_API bool showAuditLogs();
WAF_GHM_API bool clearAuditLogs();
WAF_GHM_API bool showModSecRules();
WAF_GHM_API bool updateModSecEngineInNginxConfig(bool enable);

#ifdef __cplusplus
}
#endif

class WafGhm {
public:
    WafGhm();
    ~WafGhm();

    bool initialize();
    bool loadRule(const std::string& rule);
    bool authenticate(const std::string& username, const std::string& password);
    void shutdown();
    bool setModSecurityPower(bool enable);
    bool logUserAccess(const std::string& username);
    bool showLogs();
    bool toggleProtectionForHost(const std::string& host, bool enable);
    bool isModSecurityEnabled();  
    bool showAuditLogs();
    bool clearAuditLogs();
    bool showModSecRules();
    bool updateModSecEngineInNginxConfig(bool enable);

private:
    modsecurity::ModSecurity* modsec;
    modsecurity::RulesSet* rules;
    bool modSecurityEnabled;
    std::map<std::string, bool> hostProtectionMap;  

    const std::string validUsername = "test";
    const std::string validPassword = "test";
    const std::string logFile = "user_access.log";
};

#endif // WAF_GHM_H
