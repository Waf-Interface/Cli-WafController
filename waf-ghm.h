#ifndef WAF_GHM_H
#define WAF_GHM_H

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <string>

class WafGhm {
public:
    WafGhm();
    ~WafGhm();
    bool initialize();
    bool loadRule(const std::string& rule);
    bool authenticate(const std::string& username, const std::string& password);
    void shutdown();

private:
    ModSecurity::ModSecurity* modsec;
    ModSecurity::RulesSet* rules;
    const std::string validUsername = "test";
    const std::string validPassword = "test";
};

#endif // WAF_GHM_H
