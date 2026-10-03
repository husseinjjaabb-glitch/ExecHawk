#include "engine.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace ExecHawk {

void Engine::registerAgent(std::shared_ptr<AgentBase> agent) {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    agents_[agent->name()] = agent;
}

void Engine::removeAgent(const std::string& name) {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    agents_.erase(name);
}

void Engine::executeAgent(const std::string& name, const std::string& target) {
    std::shared_ptr<AgentBase> agent;
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);
        auto it = agents_.find(name);
        if (it == agents_.end()) return;
        agent = it->second;
    }
    
    agent->execute(target);
    
    for (const auto& f : agent->getFindings()) {
        for (const auto& cb : callbacks_) {
            cb(f);
        }
    }
}

void Engine::executeAll(const std::string& target) {
    std::vector<std::shared_ptr<AgentBase>> agents_copy;
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);
        for (const auto& [name, agent] : agents_) {
            agents_copy.push_back(agent);
        }
    }
    
    std::vector<std::thread> threads;
    for (auto& agent : agents_copy) {
        threads.emplace_back([&agent, &target]() {
            agent->execute(target);
        });
    }
    
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    
    for (const auto& agent : agents_copy) {
        for (const auto& f : agent->getFindings()) {
            for (const auto& cb : callbacks_) {
                cb(f);
            }
        }
    }
}

std::vector<Finding> Engine::allFindings() const {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    std::vector<Finding> all;
    for (const auto& [name, agent] : agents_) {
        auto af = agent->getFindings();
        all.insert(all.end(), af.begin(), af.end());
    }
    return all;
}

std::vector<Finding> Engine::findingsBySeverity(Severity sev) const {
    auto all = allFindings();
    std::vector<Finding> filtered;
    std::copy_if(all.begin(), all.end(), std::back_inserter(filtered),
        [sev](const Finding& f) { return f.severity == sev; });
    return filtered;
}

Finding Engine::getFinding(int id) const {
    auto all = allFindings();
    for (const auto& f : all) {
        if (f.id == id) return f;
    }
    return Finding{};
}

void Engine::confirmFinding(int id) {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    for (auto& [name, agent] : agents_) {
        for (auto& f : agent->findings_) {
            if (f.id == id) {
                f.status = FindingStatus::CONFIRMED;
                for (const auto& cb : callbacks_) cb(f);
                return;
            }
        }
    }
}

void Engine::markFalsePositive(int id) {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    for (auto& [name, agent] : agents_) {
        for (auto& f : agent->findings_) {
            if (f.id == id) {
                f.status = FindingStatus::FALSE_POSITIVE;
                return;
            }
        }
    }
}

void Engine::markRemediated(int id) {
    std::lock_guard<std::mutex> lock(engine_mutex_);
    for (auto& [name, agent] : agents_) {
        for (auto& f : agent->findings_) {
            if (f.id == id) {
                f.status = FindingStatus::REMEDIATED;
                return;
            }
        }
    }
}

void Engine::onFinding(FindingCallback cb) {
    callbacks_.push_back(cb);
}

int Engine::nextFindingId() {
    return ++finding_counter_;
}

} // namespace ExecHawk