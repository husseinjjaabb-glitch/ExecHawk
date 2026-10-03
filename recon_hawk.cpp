#include "../core/engine.h"
#include <sstream>
#include <thread>
#include <chrono>

namespace ExecHawk {

struct ReconResult {
    std::string subdomain;
    std::string ip;
    int port;
    std::string service;
    std::string technology;
    int status_code;
    std::string title;
};

class ReconHawk : public AgentBase {
public:
    std::string name() const override { return "ReconHawk"; }
    std::string description() const override {
        return "Reconnaissance agent — OSINT, DNS, subdomain enum, port scan, fingerprint";
    }
    
    void execute(const std::string& target) override {
        log("[ReconHawk] Starting recon on: " + target);
        
        // Phase 1: Subdomain Enumeration
        auto subdomains = enumerateSubdomains(target);
        
        // Phase 2: DNS Resolution
        auto resolved = resolveDNS(subdomains);
        
        // Phase 3: Port Scanning
        for (const auto& sub : resolved) {
            auto ports = portScan(sub.ip);
            for (const auto& p : ports) {
                ReconResult r;
                r.subdomain = sub.subdomain;
                r.ip = sub.ip;
                r.port = p.port;
                r.service = p.service;
                results_.push_back(r);
            }
        }
        
        // Phase 4: Technology Fingerprinting
        fingerprintTechnologies();
        
        // Phase 5: Convert recon data to findings if interesting
        checkExposedServices();
        checkDNSTakeover();
        checkCORSMisconfig();
    }
    
    std::vector<Finding> getFindings() const override {
        std::lock_guard<std::mutex> lock(findings_mutex_);
        return findings_;
    }
    
    std::vector<ReconResult> getResults() const { return results_; }

private:
    std::vector<ReconResult> results_;
    
    struct SubdomainEntry {
        std::string subdomain;
        std::string ip;
    };
    
    struct PortEntry {
        int port;
        std::string service;
    };
    
    void log(const std::string& msg) {
        std::cout << msg << std::endl;
    }
    
    std::vector<SubdomainEntry> enumerateSubdomains(const std::string& domain) {
        log("[ReconHawk] Phase 1: Subdomain enumeration");
        std::vector<SubdomainEntry> subs;
        
        // Use subfinder, amass, dnsx
        std::string cmd = "subfinder -d " + domain + " -silent 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                std::string line(buffer);
                line.erase(line.find_last_not_of("\n\r") + 1);
                SubdomainEntry e;
                e.subdomain = line;
                subs.push_back(e);
            }
            pclose(pipe);
        }
        
        // Fallback: common subdomains
        if (subs.empty()) {
            std::vector<std::string> common = {
                "www", "api", "admin", "mail", "ftp", "dev",
                "staging", "test", "portal", "app", "cdn"
            };
            for (const auto& c : common) {
                SubdomainEntry e;
                e.subdomain = c + "." + domain;
                subs.push_back(e);
            }
        }
        
        log("[ReconHawk] Found " + std::to_string(subs.size()) + " subdomains");
        return subs;
    }
    
    std::vector<SubdomainEntry> resolveDNS(const std::vector<SubdomainEntry>& subs) {
        log("[ReconHawk] Phase 2: DNS resolution");
        std::vector<SubdomainEntry> resolved;
        
        for (const auto& s : subs) {
            std::string cmd = "dig +short " + s.subdomain + " A 2>/dev/null | head -1";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[128];
                if (fgets(buffer, sizeof(buffer), pipe)) {
                    std::string ip(buffer);
                    ip.erase(ip.find_last_not_of("\n\r") + 1);
                    if (!ip.empty()) {
                        SubdomainEntry e;
                        e.subdomain = s.subdomain;
                        e.ip = ip;
                        resolved.push_back(e);
                    }
                }
                pclose(pipe);
            }
        }
        
        log("[ReconHawk] Resolved " + std::to_string(resolved.size()) + " hosts");
        return resolved;
    }
    
    std::vector<PortEntry> portScan(const std::string& ip) {
        log("[ReconHawk] Phase 3: Port scan on " + ip);
        std::vector<PortEntry> ports;
        
        // nmap top ports
        std::string cmd = "nmap -sV --top-ports 1000 --open -Pn " 
                          + ip + " 2>/dev/null | grep open";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                std::string line(buffer);
                // Parse: "80/tcp open http nginx"
                PortEntry p;
                size_t slash = line.find("/");
                if (slash != std::string::npos) {
                    p.port = std::stoi(line.substr(0, slash));
                    size_t open_pos = line.find("open");
                    if (open_pos != std::string::npos) {
                        p.service = line.substr(open_pos + 5);
                        p.service.erase(p.service.find_last_not_of(" \n\r") + 1);
                    }
                }
                if (p.port > 0) ports.push_back(p);
            }
            pclose(pipe);
        }
        
        // Fallback common ports
        if (ports.empty()) {
            ports = {{80, "http"}, {443, "https"}, {8080, "http-proxy"}, 
                     {8443, "https-alt"}, {22, "ssh"}, {3306, "mysql"}};
        }
        
        return ports;
    }
    
    void fingerprintTechnologies() {
        log("[ReconHawk] Phase 4: Technology fingerprinting");
        // httpx / whatweb integration
        for (auto& r : results_) {
            std::string cmd = "httpx -u " + r.subdomain + " -silent "
                             "-status-code -title -tech-detect 2>/dev/null";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[512];
                if (fgets(buffer, sizeof(buffer), pipe)) {
                    std::string line(buffer);
                    size_t sc_pos = line.find("[");
                    if (sc_pos != std::string::npos) {
                        r.status_code = std::stoi(line.substr(sc_pos + 1, 3));
                    }
                }
                pclose(pipe);
            }
        }
    }
    
    void checkExposedServices() {
        for (const auto& r : results_) {
            if (r.port == 3306 || r.port == 5432 || r.port == 6379 ||
                r.port == 27017 || r.port == 9200) {
                Finding f;
                f.id = Engine::instance().nextFindingId();
                f.title = "Exposed Database Service";
                f.description = "Database service " + r.service + 
                               " is exposed on port " + std::to_string(r.port);
                f.severity = Severity::HIGH;
                f.status = FindingStatus::CONFIRMED;
                f.vulnerability_type = "Information Disclosure";
                f.affected_endpoint = r.subdomain + ":" + std::to_string(r.port);
                f.target = r.subdomain;
                f.mitre_tactic = "Discovery";
                f.mitre_technique = "T1046 - Network Service Discovery";
                f.remediation = "Restrict database port access via firewall rules. "
                               "Bind service to localhost only.";
                f.poc = "nmap -p" + std::to_string(r.port) + " " + r.ip;
                addFinding(f);
            }
            
            if (r.port == 22) {
                Finding f;
                f.id = Engine::instance().nextFindingId();
                f.title = "SSH Service Exposed";
                f.description = "SSH service accessible from external network";
                f.severity = Severity::MEDIUM;
                f.status = FindingStatus::CONFIRMED;
                f.vulnerability_type = "Information Disclosure";
                f.affected_endpoint = r.subdomain + ":22";
                f.target = r.subdomain;
                f.mitre_tactic = "Initial Access";
                f.mitre_technique = "T1021.004 - SSH Remote Copy";
                f.remediation = "Restrict SSH access to VPN/whitelisted IPs. "
                               "Use key-based auth only. Change default port.";
                f.poc = "ssh " + r.ip;
                addFinding(f);
            }
        }
    }
    
    void checkDNSTakeover() {
        // Check for dangling CNAME / subdomain takeover
        for (const auto& r : results_) {
            std::string cmd = "dig +short " + r.subdomain + " CNAME 2>/dev/null";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    std::string cname(buffer);
                    cname.erase(cname.find_last_not_of("\n\r") + 1);
                    // Check if CNAME points to unregistered service
                    if (cname.find("amazonaws.com") != std::string::npos ||
                        cname.find("azurewebsites.net") != std::string::npos ||
                        cname.find("herokuapp.com") != std::string::npos) {
                        Finding f;
                        f.id = Engine::instance().nextFindingId();
                        f.title = "Potential Subdomain Takeover";
                        f.description = "CNAME points to " + cname + 
                                       " — may be vulnerable to subdomain takeover";
                        f.severity = Severity::HIGH;
                        f.status = FindingStatus::CONFIRMED;
                        f.vulnerability_type = "Subdomain Takeover";
                        f.affected_endpoint = r.subdomain;
                        f.target = r.subdomain;
                        f.mitre_tactic = "Initial Access";
                        f.mitre_technique = "T1190 - Exploit Public-Facing App";
                        f.remediation = "Remove dangling DNS records. "
                                       "Verify all CNAME targets are active.";
                        f.poc = "dig " + r.subdomain + " CNAME";
                        addFinding(f);
                    }
                }
                pclose(pipe);
            }
        }
    }
    
    void checkCORSMisconfig() {
        for (const auto& r : results_) {
            if (r.port == 80 || r.port == 443 || r.port == 8080) {
                std::string origin = "https://evil-" + r.subdomain;
                std::string cmd = "curl -sI -H 'Origin: " + origin + "' https://" 
                                 + r.subdomain + " 2>/dev/null | grep -i "
                                 "'access-control-allow-origin'";
                FILE* pipe = popen(cmd.c_str(), "r");
                if (pipe) {
                    char buffer[256];
                    if (fgets(buffer, sizeof(buffer), pipe)) {
                        std::string header(buffer);
                        if (header.find(origin) != std::string::npos ||
                            header.find("*") != std::string::npos) {
                            Finding f;
                            f.id = Engine::instance().nextFindingId();
                            f.title = "CORS Misconfiguration";
                            f.description = "Reflects arbitrary Origin — allows cross-origin reads";
                            f.severity = Severity::MEDIUM;
                            f.status = FindingStatus::CONFIRMED;
                            f.vulnerability_type = "CORS Misconfiguration";
                            f.affected_endpoint = r.subdomain;
                            f.target = r.subdomain;
                            f.mitre_tactic = "Initial Access";
                            f.mitre_technique = "T1189 - Drive-By Compromise";
                            f.remediation = "Whitelist specific trusted origins. "
                                           "Never reflect arbitrary Origin headers.";
                            f.poc = "curl -H 'Origin: https://evil.com' -I https://" 
                                   + r.subdomain;
                            addFinding(f);
                        }
                    }
                    pclose(pipe);
                }
            }
        }
    }
};

} // namespace ExecHawk