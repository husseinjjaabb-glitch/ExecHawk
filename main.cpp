#include "core/engine.h"
#include "core/orchestrator.cpp"
#include "agents/recon_hawk.cpp"
#include "agents/vuln_hawk.cpp"
#include "agents/exploit_hawk.cpp"
#include "agents/post_hawk.cpp"
#include "reporting/report_generator.cpp"
#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "\n🦅 Exec Hawk AI Agent Platform v1.0\n";
    std::cout << "══════════════════════════════════\n\n";
    
    if (argc < 2) {
        std::cout << "Usage: exec_hawk <target>\n";
        std::cout << "Example: exec_hawk https://api.target.com\n";
        return 1;
    }
    
    std::string target = argv[1];
    auto& engine = ExecHawk::Engine::instance();
    ExecHawk::ReportGenerator reporter("./reports");
    
    // Auto-report on new findings
    engine.onFinding([&reporter](const ExecHawk::Finding& f) {
        reporter.generateFindingMarkdown(f);
        
        std::string sev_icon;
        switch(f.severity) {
            case ExecHawk::Severity::CRITICAL: sev_icon = "🔴"; break;
            case ExecHawk::Severity::HIGH:     sev_icon = "🟠"; break;
            case ExecHawk::Severity::MEDIUM:   sev_icon = "🟡"; break;
            case ExecHawk::Severity::LOW:      sev_icon = "🟢"; break;
            default:                           sev_icon = "🔵"; break;
        }
        
        std::cout << sev_icon << " [" << f.severityToString() << "] #" 
                  << f.id << " — " << f.title << "\n"
                  << "   Type: " << f.vulnerability_type << "\n"
                  << "   Endpoint: " << f.affected_endpoint << "\n\n";
    });
    
    // Register all agents
    auto recon   = std::make_shared<ExecHawk::ReconHawk>();
    auto vuln    = std::make_shared<ExecHawk::VulnHawk>();
    auto exploit = std::make_shared<ExecHawk::ExploitHawk>();
    auto post    = std::make_shared<ExecHawk::PostHawk>();
    
    engine.registerAgent(recon);
    engine.registerAgent(vuln);
    engine.registerAgent(exploit);
    engine.registerAgent(post);
    
    std::cout << "Registered Agents:\n";
    std::cout << "  ├─ ReconHawk    — Reconnaissance\n";
    std::cout << "  ├─ VulnHawk     — Vulnerability Discovery\n";
    std::cout << "  ├─ ExploitHawk  — Exploitation\n";
    std::cout << "  └─ PostHawk     — Post-Exploitation\n\n";
    
    // Execute kill chain
    ExecHawk::Orchestrator orch;
    orch.run(target);
    
    // Final report
    auto all = engine.allFindings();
    reporter.generateFullReport(all, "exec_hawk_final");
    
    std::cout << "\n══════════════════════════════════\n";
    std::cout << "🦅 Hunt Complete\n";
    std::cout << "   Total Findings: " << all.size() << "\n";
    std::cout << "   Reports: ./reports/\n";
    std::cout << "══════════════════════════════════\n";
    
    return 0;
}