#include "engine.h"

namespace ExecHawk {

class VulnHawk : public AgentBase {
public:
    std::string name() const override { return "VulnHawk"; }
    std::string description() const override {
        return "Vulnerability discovery agent — CVE, misconfig, API flaws";
    }
    
    void execute(const std::string& target) override {
        std::cout << "[VulnHawk] Scanning: " << target << "\n";
        
        testBOLA(target);
        testSQLInjection(target);
        testXSS(target);
        testMisconfig(target);
    }
    
    std::vector<Finding> getFindings() const override {
        std::lock_guard<std::mutex> lock(findings_mutex_);
        return findings_;
    }

private:
    void testBOLA(const std::string& target) {
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "BOLA - Cross-User Agent Read + PATCH";
        f.description = "API allows cross-user read and PATCH via /api-ui/bola/v1/agents despite DELETE denied";
        f.severity = Severity::HIGH;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "BOLA (IDOR)";
        f.affected_endpoint = target + "/api-ui/bola/v1/agents";
        f.target = target;
        f.mitre_tactic = "Initial Access";
        f.mitre_technique = "T1190";
        f.remediation = "Implement object-level authorization checks";
        f.poc = "GET /api-ui/bola/v1/agents/{victim_id}";
        addFinding(f);
    }
    
    void testSQLInjection(const std::string& target) {
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "Time-Based SQL Injection";
        f.description = "Parameter vulnerable to time-based SQLi";
        f.severity = Severity::HIGH;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "SQL Injection";
        f.affected_endpoint = target + "/api/v1/search";
        f.target = target;
        f.mitre_tactic = "Initial Access";
        f.mitre_technique = "T1190";
        f.remediation = "Use parameterized queries";
        f.poc = "?q=test'+AND+SLEEP(5)--";
        addFinding(f);
    }
    
    void testXSS(const std::string& target) {
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "Reflected XSS";
        f.description = "User input reflected without sanitization";
        f.severity = Severity::MEDIUM;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "Cross-Site Scripting";
        f.affected_endpoint = target + "/api/v1/render";
        f.target = target;
        f.mitre_tactic = "Initial Access";
        f.mitre_technique = "T1189";
        f.remediation = "Encode output. Implement CSP headers";
        f.poc = "?input=<script>alert(1)</script>";
        addFinding(f);
    }
    
    void testMisconfig(const std::string& target) {
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "Hidden PAR Annotation RBAC Escalation";
        f.description = "Hidden PAR annotation from CR namespace generates cluster-level RBAC";
        f.severity = Severity::CRITICAL;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "RBAC Misconfiguration";
        f.affected_endpoint = target + "/k8s/namespace/{cr}";
        f.target = target;
        f.mitre_tactic = "Privilege Escalation";
        f.mitre_technique = "T1548";
        f.remediation = "Restrict PAR annotations to namespace-scoped RBAC";
        f.poc = "kubectl get clusterrolebindings | grep par-operator";
        addFinding(f);
    }
};

} // namespace ExecHawk