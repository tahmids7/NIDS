/**
 * @file nids.h
 * @brief Main Network Intrusion Detection System class
 */

#ifndef NIDS_H
#define NIDS_H

#include <string>
#include <memory>
#include "packet_capture.h"
#include "rule_engine.h"
#include "alert_system.h"
#include "log_manager.h"
#include "config_manager.h"

/**
 * @class NIDS
 * @brief Core Network Intrusion Detection System class
 * 
 * Manages all components of the NIDS, including packet capture,
 * rule processing, alerting and logging.
 */
class NIDS {
public:
    /**
     * @brief Constructor
     * @param configPath Path to configuration file
     */
    NIDS(const std::string& configPath);
    
    /**
     * @brief Destructor
     */
    ~NIDS();
    
    /**
     * @brief Initialize the NIDS
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * @brief Start the NIDS
     * @return True if start succeeded, false otherwise
     */
    bool start();
    
    /**
     * @brief Stop the NIDS
     */
    void stop();
    
    /**
     * @brief Check if the NIDS is running
     * @return True if running, false otherwise
     */
    bool isRunning() const;
    
    /**
     * @brief Get status information about the NIDS
     * @return Status string
     */
    std::string getStatus() const;

private:
    std::unique_ptr<ConfigManager> m_configManager;
    std::unique_ptr<PacketCapture> m_packetCapture;
    std::unique_ptr<RuleEngine> m_ruleEngine;
    std::unique_ptr<AlertSystem> m_alertSystem;
    std::unique_ptr<LogManager> m_logManager;
    
    bool m_initialized;
    bool m_running;
    
    /**
     * @brief Process a captured packet
     * @param packet The packet data
     * @param header The packet header
     */
    void processPacket(const uint8_t* packet, const struct pcap_pkthdr* header);
};

#endif // NIDS_H
