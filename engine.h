#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>

namespace ExecHawk {

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class FindingStatus {
    UNCONFIRMED,
    CONFIRMED,
    FALSE_POSITIVE,
    ACCEPTED_RISK,
    REMEDIATED
};

struct Finding {
    int id;
    std::string title;
    std::string description;
    Severity severity;
    FindingStatus status;
    std::string target;
    std::string report_id;
    std::string vulnerability_type;
    std::string affected_endpoint;
    std::string remediation;
    std::string poc;
    std::string mitre_tactic;
    std::string mitre_technique;
    std::string timestamp;
    
    std::string severityToString() const {
        switch(severity) {
            case Severity::INFO:     return "INFO";
            case Severity::LOW:      return "LOW";
            case Severity::MEDIUM:   return "MEDIUM";
            case Severity::HIGH:     return "HIGH";
            case Severity::CRITICAL: return "CRITICAL";
        }
        return "UNKNOWN";
    }
    
    std::string statusToString() const {
        switch(status) {
            case FindingStatus::UNCONFIRMED:    return "UNCONFIRMED";
            case FindingStatus::CONFIRMED:      return "CONFIRMED";
            case FindingStatus::FALSE_POSITIVE: return "FALSE_POSITIVE";
            case FindingStatus::ACCEPTED_RISK:  return "ACCEPTED_RISK";
            case FindingStatus::REMEDIATED:     return "REMEDIATED";
        }
        return "UNKNOWN";
    }
};

class AgentBase {
public:
    virtual ~AgentBase() = default;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;
    virtual void execute(const std::string& target) = 0;
    virtual std::vector<Finding> getFindings() const = 0;
    
    void addFinding(const Finding& f) {
        std::lock_guard<std::mutex> lock(findings_mutex_);
        findings_.push_back(f);
    }
    
protected:
    std::vector<Finding> findings_;
    mutable std::mutex findings_mutex_;
};

class Engine {
public:
    static Engine& instance() {
        static Engine e;
        return e;
    }
    
    void registerAgent(std::shared_ptr<AgentBase> agent);
    void removeAgent(const std::string& name);
    void executeAgent(const std::string& name, const std::string& target);
    void executeAll(const std::string& target);
    
    std::vector<Finding> allFindings() const;
    std::vector<Finding> findingsBySeverity(Severity sev) const;
    Finding getFinding(int id) const;
    
    void confirmFinding(int id);
    void markFalsePositive(int id);
    void markRemediated(int id);
    
    using FindingCallback = std::function<void(const Finding&)>;
    void onFinding(FindingCallback cb);
    
    int nextFindingId();
    
private:
    Engine() = default;
    
    std::unordered_map<std::string, std::shared_ptr<AgentBase>> agents_;
    std::vector<FindingCallback> callbacks_;
    std::atomic<int> finding_counter_{0};
    mutable std::mutex engine_mutex_;
};

} // namespace ExecHawk