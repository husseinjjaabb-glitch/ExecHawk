#include "engine.h"
#include <fstream>
#include <filesystem>

namespace ExecHawk {

class ReportGenerator {
public:
    ReportGenerator(const std::string& output_dir = "./reports")
        : output_dir_(output_dir) {
        std::filesystem::create_directories(output_dir_);
    }
    
    void generateFindingMarkdown(const Finding& f) {
        std::string filename = "finding-" + std::to_string(f.id) + ".md";
        std::ofstream out(output_dir_ + "/" + filename);
        
        out << "# Finding #" << f.id << " [" << f.severityToString() << "]\n\n";
        out << "**Status:** " << f.statusToString() << "\n\n";
        out << "**Title:** " << f.title << "\n\n";
        out << "**Type:** " << f.vulnerability_type << "\n\n";
        out << "**Endpoint:** `" << f.affected_endpoint << "`\n\n";
        out << "**Target:** " << f.target << "\n\n";
        out << "**MITRE:** " << f.mitre_tactic << " → " << f.mitre_technique << "\n\n";
        out << "---\n\n## Description\n\n" << f.description << "\n\n";
        out << "## PoC\n\n```\n" << f.poc << "\n```\n\n";
        out << "## Remediation\n\n" << f.remediation << "\n\n";
        out << "---\n*Exec Hawk*\n";
        out.close();
    }
    
    void generateFullReport(const std::vector<Finding>& findings,
                           const std::string& name) {
        std::ofstream out(output_dir_ + "/" + name + ".md");
        
        out << "# Exec Hawk — Penetration Test Report\n\n## Summary\n\n";
        out << "| Severity | Count |\n|---|---|\n";
        
        for (int i = 4; i >= 0; --i) {
            auto sev = static_cast<Severity>(i);
            auto count = std::count_if(findings.begin(), findings.end(),
                [sev](const Finding& f) { return f.severity == sev; });
            Finding tmp; tmp.severity = sev;
            out << "| " << tmp.severityToString() << " | " << count << " |\n";
        }
        
        out << "\n## Findings\n\n";
        for (const auto& f : findings) {
            out << "- **#" << f.id << " [" << f.severityToString() << "]** " 
                << f.title << "\n";
        }
        out.close();
    }
    
private:
    std::string output_dir_;
};

} // namespace ExecHawk