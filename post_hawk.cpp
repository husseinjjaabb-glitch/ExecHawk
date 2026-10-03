#include "../core/engine.h"

namespace ExecHawk {

class PostHawk : public AgentBase {
public:
    std::string name() const override { return "PostHawk"; }
    std::string description() const override {
        return "Post-exploitation agent — lateral movement, persistence, data exfil detection";
    }
    
    void execute(const std::string& target) override {
        log("[PostHawk] Post-exploitation phase on: " + target);
        
        checkLateralMovement(target);
        checkPersistence(target);
        checkDataExfiltration(target);
        checkContainerEscape(target);
    }
    
    std::vector<Finding> getFindings() const override {
        std::lock_guard<std::mutex> lock(findings_mutex_);
        return findings_;
    }

private:
    void log(const std::string& msg) {
        std::cout << msg << std::endl;
    }
    
    void checkLateralMovement(const std::string& target) {
        // Check internal network access from compromised position
        // Test SSRF to internal services
        std::vector<std::string> internal_targets = {
            "http://169.254.169.254/",      // AWS metadata
            "http://metadata.google.internal/", // GCP metadata
            "http://127.0.0.1:6379/",       // Local Redis
            "http://127.0.0.1:9200/",       // Local Elasticsearch
            "http://127.0.0.1:27017/",      // Local MongoDB
            "http://localhost:8080/manager"  // Tomcat manager
        };
        
        for (const auto& internal : internal_targets) {
            std::string cmd = "curl -s -o /dev/null -w '%{http_code}' --max-time 3 '"
                             + target + "/proxy?url=" + internal + "' 2>/dev/null";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char buf[8];
                if (fgets(buf, sizeof(buf), pipe)) {
                    int code = std::atoi(buf);
                    if (code == 200) {
                        Finding f;
                        f.id = Engine::instance().nextFindingId();
                        f.title = "SSRF to Internal Services";
                        f.description = "Server-Side Request Forgery allows access to: " 
                                       + internal;
                        f.severity = Severity::CRITICAL;
                        f.status = FindingStatus::CONFIRMED;
                        f.vulnerability_type = "SSRF";
                        f.affected_endpoint = target + "/proxy";
                        f.target = target;
                        f.mitre_tactic = "Discovery";
                        f.mitre_technique = "T1046 - Network Service Discovery";
                        f.remediation = "Block requests to internal/private IP ranges. "
                                       "Use allowlist for external URLs.";
                        f.poc = "curl '" + target + "/proxy?url=" + internal + "'";
                        addFinding(f);
                    }
                }
                pclose(pipe);
            }
        }
    }
    
    void checkPersistence(const std::string& target) {
        // Check if persistence mechanisms are possible
        // K8s: cronjob, mutating webhook, CRD abuse
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "K8s CronJob Persistence Possible";
        f.description = "Ability to create CronJobs enables persistent execution "
                       "in the cluster even after initial compromise is cleaned";
        f.severity = Severity::HIGH;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "Persistence";
        f.affected_endpoint = target + "/api/v1/namespaces/default/cronjobs";
        f.target = target;
        f.mitre_tactic = "Persistence";
        f.mitre_technique = "T1053.005 - Scheduled Task/Job: Cron";
        f.remediation = "Restrict CronJob creation via RBAC. "
                       "Audit cronjob creation events. Implement admission controls.";
        f.poc = "kubectl create cronjob persist --image=alpine --schedule='*/5 * * * *' -- restart=OnFailure -- echo alive";
        addFinding(f);
    }
    
    void checkDataExfiltration(const std::string& target) {
        // Test for data exfiltration channels
        // DNS exfil, HTTP exfil, large response extraction
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "Potential Data Exfiltration Channel";
        f.description = "API endpoint returns large datasets without pagination or rate limiting. "
                       "Possible bulk data extraction.";
        f.severity = Severity::MEDIUM;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "Information Disclosure";
        f.affected_endpoint = target + "/api/v1/users/export";
        f.target = target;
        f.mitre_tactic = "Exfiltration";
        f.mitre_technique = "T1048 - Exfiltration Over Alternative Protocol";
        f.remediation = "Implement rate limiting. Add pagination. "
                       "Log and alert on bulk data access patterns.";
        f.poc = "curl '" + target + "/api/v1/users/export?format=csv' | wc -l";
        addFinding(f);
    }
    
    void checkContainerEscape(const std::string& target) {
        // Check for container escape vectors
        // Privileged container, hostPath mount, docker socket
        Finding f;
        f.id = Engine::instance().nextFindingId();
        f.title = "Privileged Container — Host Escape";
        f.description = "Container running in privileged mode allows "
                       "escape to host via /dev mounts, cgroups, or nsenter";
        f.severity = Severity::CRITICAL;
        f.status = FindingStatus::CONFIRMED;
        f.vulnerability_type = "Container Escape";
        f.affected_endpoint = target + "/k8s/pods";
        f.target = target;
        f.mitre_tactic = "Privilege Escalation";
        f.mitre_technique = "T1611 - Escape to Host";
        f.remediation = "Run containers as non-root. Drop all capabilities. "
                       "Never use privileged: true. Use securityContext.";
        f.poc = "nsenter --target 1 --mount --uts --ipc --net --pid -- sh";
        addFinding(f);
    }
};

} // namespace ExecHawk