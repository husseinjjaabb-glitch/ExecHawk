#include "engine.h"
#include <queue>
#include <condition_variable>

namespace ExecHawk {

enum class Phase {
    RECON,
    VULN_SCAN,
    EXPLOIT,
    POST_EXPLOIT,
    REPORT,
    COMPLETE
};

struct Task {
    std::string agent_name;
    std::string target;
    Phase phase;
    int priority;
};

class Orchestrator {
public:
    Orchestrator() : current_phase_(Phase::RECON) {}
    
    void addTask(const Task& t) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        task_queue_.push(t);
        cv_.notify_one();
    }
    
    void run(const std::string& target) {
        auto& engine = Engine::instance();
        
        std::cout << "\n🦅 Exec Hawk — Orchestrator\n";
        std::cout << "════════════════════════════════\n\n";
        
        // PTES Kill Chain Execution
        executePhase(Phase::RECON, target, "ReconHawk");
        executePhase(Phase::VULN_SCAN, target, "VulnHawk");
        executePhase(Phase::EXPLOIT, target, "ExploitHawk");
        executePhase(Phase::POST_EXPLOIT, target, "PostHawk");
        
        // Cross-phase correlation
        correlateFindings();
        
        current_phase_ = Phase::COMPLETE;
        std::cout << "\n🦅 Kill chain complete.\n";
    }
    
    Phase currentPhase() const { return current_phase_; }
    
private:
    Phase current_phase_;
    std::queue<Task> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    
    void executePhase(Phase phase, const std::string& target, 
                      const std::string& agent_name) {
        current_phase_ = phase;
        std::string phase_name = phaseToString(phase);
        
        std::cout << "[▶] Phase: " << phase_name << "\n";
        std::cout << "    Agent: " << agent_name << "\n";
        std::cout << "    Target: " << target << "\n\n";
        
        Engine::instance().executeAgent(agent_name, target);
        
        auto findings = Engine::instance().allFindings();
        std::cout << "[✓] " << phase_name << " complete. "
                  << findings.size() << " total findings.\n\n";
    }
    
    void correlateFindings() {
        std::cout << "[~] Cross-phase correlation...\n";
        
        auto findings = Engine::instance().allFindings();
        
        // Link SSRF findings to internal service discoveries
        // Link auth bypass to privilege escalation chains
        // Map all findings to MITRE ATT&CK
        
        for (const auto& f : findings) {
            std::cout << "  [#" << f.id << "] " 
                      << f.severityToString() << " — " 
                      << f.title << "\n"
                      << "    MITRE: " << f.mitre_tactic 
                      << " → " << f.mitre_technique << "\n";
        }
    }
    
    std::string phaseToString(Phase p) {
        switch(p) {
            case Phase::RECON:         return "Reconnaissance";
            case Phase::VULN_SCAN:     return "Vulnerability Scanning";
            case Phase::EXPLOIT:       return "Exploitation";
            case Phase::POST_EXPLOIT:  return "Post-Exploitation";
            case Phase::REPORT:        return "Reporting";
            case Phase::COMPLETE:      return "Complete";
        }
        return "Unknown";
    }
};

} // namespace ExecHawk