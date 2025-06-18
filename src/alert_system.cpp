/**
 * @file alert_system.cpp
 * @brief Implementation of the alert system
 */

#include "alert_system.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

AlertSystem::AlertSystem() : m_nextAlertId(1) {
}

AlertSystem::~AlertSystem() {
}

bool AlertSystem::initialize() {
    // Initialize the alert system
    // This is a simple implementation, so there's not much to initialize
    return true;
}

int AlertSystem::generateAlert(int ruleId, const std::string& message,
                              const std::string& sourceIp, const std::string& destIp,
                              int sourcePort, int destPort, const std::string& protocol,
                              int severity) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Create a new alert
    auto alert = std::make_shared<Alert>();
    alert->id = m_nextAlertId++;
    alert->ruleId = ruleId;
    alert->message = message;
    alert->timestamp = getCurrentTimestamp();
    alert->sourceIp = sourceIp;
    alert->destIp = destIp;
    alert->sourcePort = sourcePort;
    alert->destPort = destPort;
    alert->protocol = protocol;
    alert->severity = severity;
    
    // Add the alert to the list
    m_alerts.push_back(alert);
    
    // Notify callbacks about the new alert
    notifyCallbacks(*alert);
    
    return alert->id;
}

std::shared_ptr<Alert> AlertSystem::getAlert(int alertId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& alert : m_alerts) {
        if (alert->id == alertId) {
            return alert;
        }
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<Alert>> AlertSystem::getAllAlerts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_alerts;
}

void AlertSystem::registerCallback(AlertCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callbacks.push_back(callback);
}

std::string AlertSystem::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void AlertSystem::notifyCallbacks(const Alert& alert) {
    for (const auto& callback : m_callbacks) {
        try {
            callback(alert);
        } catch (const std::exception& ex) {
            std::cerr << "Exception in alert callback: " << ex.what() << std::endl;
        }
    }
}
