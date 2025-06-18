/**
 * @file rule_engine.h
 * @brief Rule processing engine that integrates with Snort
 */

#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations
struct SnortConfig;
struct Packet;
struct pcap_pkthdr;

/**
 * @class RuleEngine
 * @brief Processes packets against Snort rules
 */
class RuleEngine {
public:
    /**
     * @brief Callback type for rule matches
     */
    using AlertCallback = std::function<void(int sid, const std::string& msg, const uint8_t* packet, const pcap_pkthdr* header)>;
    
    /**
     * @brief Constructor
     * @param rulesDir Directory containing Snort rules
     * @param configPath Path to Snort configuration file
     */
    RuleEngine(const std::string& rulesDir, const std::string& configPath);
    
    /**
     * @brief Destructor
     */
    ~RuleEngine();
    
    /**
     * @brief Initialize the rule engine
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * @brief Set the alert callback
     * @param callback Function to call when a rule matches
     */
    void setAlertCallback(AlertCallback callback);
    
    /**
     * @brief Process a packet against the rules
     * @param packet The packet data
     * @param header The packet header
     * @return True if packet matched any rules, false otherwise
     */
    bool processPacket(const uint8_t* packet, const struct pcap_pkthdr* header);
    
    /**
     * @brief Reload rules
     * @return True if rules were reloaded successfully, false otherwise
     */
    bool reloadRules();
    
    /**
     * @brief Get error message if an operation failed
     * @return Error message
     */
    std::string getLastError() const;

private:
    std::string m_rulesDir;
    std::string m_configPath;
    SnortConfig* m_snortConfig;
    AlertCallback m_alertCallback;
    std::string m_lastError;
    bool m_initialized;
    
    /**
     * @brief Initialize Snort detection engine
     * @return True if initialization succeeded, false otherwise
     */
    bool initSnort();
    
    /**
     * @brief Clean up Snort resources
     */
    void cleanupSnort();
    
    /**
     * @brief Convert raw packet to Snort packet structure
     * @param rawPacket Raw packet data
     * @param header Packet header
     * @return Snort packet structure
     */
    Packet* convertToSnortPacket(const uint8_t* rawPacket, const struct pcap_pkthdr* header);
};

#endif // RULE_ENGINE_H
