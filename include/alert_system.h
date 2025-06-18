/**
 * @file alert_system.h
 * @brief System for generating and managing alerts
 */

#ifndef ALERT_SYSTEM_H
#define ALERT_SYSTEM_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>

/**
 * @struct Alert
 * @brief Represents a single alert
 */
struct Alert {
    int id;                     ///< Alert ID
    int ruleId;                 ///< ID of the rule that triggered the alert
    std::string message;        ///< Alert message
    std::string timestamp;      ///< Time when the alert was generated
    std::string sourceIp;       ///< Source IP address
    std::string destIp;         ///< Destination IP address
    int sourcePort;             ///< Source port
    int destPort;               ///< Destination port
    std::string protocol;       ///< Protocol (TCP, UDP, etc.)
    int severity;               ///< Alert severity (1-5, with 1 being highest)
    
    /**
     * @brief Constructor
     */
    Alert() : id(0), ruleId(0), sourcePort(0), destPort(0), severity(3) {}
};

/**
 * @class AlertSystem
 * @brief Manages system alerts
 */
class AlertSystem {
public:
    /**
     * @brief Callback type for new alerts
     */
    using AlertCallback = std::function<void(const Alert&)>;
    
    /**
     * @brief Constructor
     */
    AlertSystem();
    
    /**
     * @brief Destructor
     */
    ~AlertSystem();
    
    /**
     * @brief Initialize the alert system
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * @brief Generate a new alert
     * @param ruleId Rule ID that triggered the alert
     * @param message Alert message
     * @param sourceIp Source IP address
     * @param destIp Destination IP address
     * @param sourcePort Source port
     * @param destPort Destination port
     * @param protocol Protocol
     * @param severity Alert severity
     * @return Generated alert ID
     */
    int generateAlert(int ruleId, const std::string& message,
                     const std::string& sourceIp, const std::string& destIp,
                     int sourcePort, int destPort, const std::string& protocol,
                     int severity);
    
    /**
     * @brief Get a specific alert by ID
     * @param alertId Alert ID
     * @return Alert object if found, nullptr otherwise
     */
    std::shared_ptr<Alert> getAlert(int alertId) const;
    
    /**
     * @brief Get all alerts
     * @return Vector of all alerts
     */
    std::vector<std::shared_ptr<Alert>> getAllAlerts() const;
    
    /**
     * @brief Register callback for new alerts
     * @param callback Function to call for each new alert
     */
    void registerCallback(AlertCallback callback);

private:
    std::vector<std::shared_ptr<Alert>> m_alerts;
    int m_nextAlertId;
    std::vector<AlertCallback> m_callbacks;
    mutable std::mutex m_mutex;
    
    /**
     * @brief Get current timestamp as string
     * @return Current timestamp
     */
    std::string getCurrentTimestamp() const;
    
    /**
     * @brief Notify all registered callbacks about a new alert
     * @param alert The new alert
     */
    void notifyCallbacks(const Alert& alert);
};

#endif // ALERT_SYSTEM_H
