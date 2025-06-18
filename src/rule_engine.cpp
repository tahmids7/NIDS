/**
 * @file rule_engine.cpp
 * @brief Implementation of the rule engine that interfaces with Snort
 */

#include "rule_engine.h"
#include <stdexcept>
#include <iostream>
#include <fstream>   // Added for std::ifstream
#include <cstring>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>  // Include the pcap definitions

// Forward declarations for Snort types - in a real implementation,
// we would include the Snort headers directly, but for this example
// we're using a simplified approach
struct SnortPacket {
    const struct pcap_pkthdr* header;
    const uint8_t* data;
    // Additional fields would be here in a real implementation
};

RuleEngine::RuleEngine(const std::string& rulesDir, const std::string& configPath)
    : m_rulesDir(rulesDir), m_configPath(configPath), 
      m_snortConfig(nullptr), m_initialized(false) {
}

RuleEngine::~RuleEngine() {
    if (m_initialized) {
        cleanupSnort();
    }
}

bool RuleEngine::initialize() {
    // Initialize Snort
    if (!initSnort()) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

bool RuleEngine::initSnort() {
    // In a real implementation, we would initialize the Snort library directly.
    // However, for this simplified example, we'll use custom rule loading
    
    std::cout << "Initializing rule engine with directory: " << m_rulesDir << std::endl;
    
    // Check if rules directory exists and local.rules is readable
    std::string rulesFile = m_rulesDir + "/local.rules";
    std::ifstream ruleStream(rulesFile);
    
    if (!ruleStream.is_open()) {
        m_lastError = "Rules file does not exist or is not readable: " + rulesFile;
        std::cerr << m_lastError << std::endl;
        
        // Try alternative path
        rulesFile = m_rulesDir + "/snort_rules/local.rules";
        std::cout << "Trying alternative rules path: " << rulesFile << std::endl;
        ruleStream = std::ifstream(rulesFile);
        
        if (!ruleStream.is_open()) {
            m_lastError = "Rules file not found. We've tried: " + m_rulesDir + "/local.rules and " + rulesFile;
            std::cerr << m_lastError << std::endl;
            // For development purposes, let's create a simple test rule file
            std::cout << "Creating a sample rules file for testing..." << std::endl;
            std::ofstream sampleRules(rulesFile);
            if (sampleRules.is_open()) {
                sampleRules << "# Sample Snort rule file for development\n";
                sampleRules << "# Format: action proto src_ip src_port -> dst_ip dst_port (msg:\"Message\"; sid:1000; rev:1;)\n\n";
                sampleRules << "alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; sid:1001; rev:1;)\n";
                sampleRules << "alert tcp any any -> any 22 (msg:\"SSH Traffic\"; sid:1002; rev:1;)\n";
                sampleRules << "alert icmp any any -> any any (msg:\"ICMP Traffic\"; sid:1003; rev:1;)\n";
                sampleRules.close();
                std::cout << "Sample rules file created at: " << rulesFile << std::endl;
                // Reopen for reading
                ruleStream = std::ifstream(rulesFile);
                if (!ruleStream.is_open()) {
                    m_lastError = "Failed to read newly created rules file: " + rulesFile;
                    std::cerr << m_lastError << std::endl;
                    return false;
                }
            } else {
                m_lastError = "Failed to create sample rules file. Permission issue?";
                std::cerr << m_lastError << std::endl;
                return false;
            }
        }
    }
    
    std::cout << "Successfully opened rules file: " << rulesFile << std::endl;
    
    // In a real implementation, we would parse the rules file here
    // For this simulation, we'll just read it for verification
    std::string line;
    int ruleCount = 0;
    
    while (std::getline(ruleStream, line)) {
        if (!line.empty() && line[0] != '#') {
            // It's a rule (not a comment)
            ruleCount++;
        }
    }
    
    std::cout << "Loaded " << ruleCount << " rules from " << rulesFile << std::endl;
    
    // In a production system, we would initialize Snort with the config
    // For this example, we'll just check if the config file exists
    if (!m_configPath.empty()) {
        std::ifstream configStream(m_configPath);
        if (!configStream.is_open()) {
            std::cout << "Warning: Snort config file not found: " << m_configPath << std::endl;
            std::cout << "Using default configuration instead" << std::endl;
        } else {
            std::cout << "Found Snort config file: " << m_configPath << std::endl;
            configStream.close();
        }
    }
    
    return true;
}

void RuleEngine::cleanupSnort() {
    // Cleanup would release Snort resources in a real implementation
    m_initialized = false;
}

void RuleEngine::setAlertCallback(AlertCallback callback) {
    m_alertCallback = callback;
}

bool RuleEngine::processPacket(const uint8_t* packet, const struct pcap_pkthdr* header) {
    if (!m_initialized) {
        m_lastError = "Rule engine not initialized";
        return false;
    }

    bool match = false;
    
    // Check if it's a simulated packet from our simulation mode
    std::string packetData(reinterpret_cast<const char*>(packet), header->caplen);
    if (packetData.find("SIMULATED PACKET") == 0) {
        // This is a simulated packet - use our simplified rule matching
        std::cout << "Processing simulated packet: " << packetData.substr(0, 50) << "..." << std::endl;
        
        // Extract source and destination IPs from the simulated packet
        std::string sourceIp = "0.0.0.0";
        std::string destIp = "0.0.0.0";
        int sourcePort = 0;
        int destPort = 0;
        std::string protocol = "UNKNOWN";
        
        // Parse basic information from the simulated packet
        size_t srcPos = packetData.find("SRC=");
        if (srcPos != std::string::npos) {
            size_t srcEnd = packetData.find(" ", srcPos);
            if (srcEnd != std::string::npos) {
                std::string srcInfo = packetData.substr(srcPos + 4, srcEnd - (srcPos + 4));
                size_t colonPos = srcInfo.find(":");
                if (colonPos != std::string::npos) {
                    sourceIp = srcInfo.substr(0, colonPos);
                    sourcePort = std::stoi(srcInfo.substr(colonPos + 1));
                } else {
                    sourceIp = srcInfo;
                }
            }
        }
        
        size_t dstPos = packetData.find("DST=");
        if (dstPos != std::string::npos) {
            size_t dstEnd = packetData.find(" ", dstPos);
            if (dstEnd != std::string::npos) {
                std::string dstInfo = packetData.substr(dstPos + 4, dstEnd - (dstPos + 4));
                size_t colonPos = dstInfo.find(":");
                if (colonPos != std::string::npos) {
                    destIp = dstInfo.substr(0, colonPos);
                    destPort = std::stoi(dstInfo.substr(colonPos + 1));
                } else {
                    destIp = dstInfo;
                }
            }
        }
        
        // Check packet type and apply appropriate rules
        if (packetData.find("TYPE=TCP") != std::string::npos) {
            protocol = "TCP";
            if (packetData.find("FLAGS=SYN") != std::string::npos && 
                (packetData.find("DST=10.0.0.1:80") != std::string::npos || 
                 packetData.find("DST=10.0.0.1:443") != std::string::npos)) {
                
                // Trigger SYN scan rule
                if (m_alertCallback) {
                    std::cout << "ALERT: Detected simulated SYN scan from " << sourceIp << ":" << sourcePort 
                              << " to " << destIp << ":" << destPort << std::endl;
                    m_alertCallback(1000, "Possible SYN scan detected (simulated)", packet, header);
                    match = true;
                }
            }
            
            if (packetData.find("PAYLOAD=") != std::string::npos &&
                (packetData.find("SELECT") != std::string::npos || 
                 packetData.find("OR 1=1") != std::string::npos ||
                 packetData.find("--") != std::string::npos ||
                 packetData.find("'") != std::string::npos)) {
                
                // Trigger SQL injection rule
                if (m_alertCallback) {
                    std::cout << "ALERT: Detected simulated SQL injection from " << sourceIp << ":" << sourcePort 
                              << " to " << destIp << ":" << destPort << std::endl;
                    m_alertCallback(1001, "Possible SQL injection attempt (simulated)", packet, header);
                    match = true;
                }
            }
            
            // XSS detection
            if (packetData.find("PAYLOAD=") != std::string::npos &&
                (packetData.find("<script>") != std::string::npos || 
                 packetData.find("onerror=") != std::string::npos ||
                 packetData.find("javascript:") != std::string::npos ||
                 packetData.find("alert(") != std::string::npos)) {
                
                // Trigger XSS rule
                if (m_alertCallback) {
                    std::cout << "ALERT: Detected simulated XSS attack from " << sourceIp << ":" << sourcePort 
                              << " to " << destIp << ":" << destPort << std::endl;
                    m_alertCallback(1004, "Possible Cross-Site Scripting attempt (simulated)", packet, header);
                    match = true;
                }
            }
            
            // Path traversal detection
            if (packetData.find("PAYLOAD=") != std::string::npos &&
                (packetData.find("../") != std::string::npos || 
                 packetData.find("..%2f") != std::string::npos ||
                 packetData.find("..\\") != std::string::npos ||
                 packetData.find("/etc/") != std::string::npos ||
                 packetData.find("passwd") != std::string::npos ||
                 packetData.find("shadow") != std::string::npos)) {
                
                // Trigger path traversal rule
                if (m_alertCallback) {
                    std::cout << "ALERT: Detected simulated path traversal attack from " << sourceIp << ":" << sourcePort 
                              << " to " << destIp << ":" << destPort << std::endl;
                    m_alertCallback(1005, "Possible Path Traversal attempt (simulated)", packet, header);
                    match = true;
                }
            }
        }
        else if (packetData.find("TYPE=UDP") != std::string::npos) {
            protocol = "UDP";
            if (packetData.find("SRC=192.168.1.10:53") != std::string::npos) {
                // Trigger DNS rule
                if (m_alertCallback) {
                    std::cout << "ALERT: Detected simulated DNS amplification from " << sourceIp << ":" << sourcePort 
                              << " to " << destIp << ":" << destPort << std::endl;
                    m_alertCallback(1002, "Possible DNS amplification response (simulated)", packet, header);
                    match = true;
                }
            }
        }
        else if (packetData.find("TYPE=ICMP") != std::string::npos) {
            protocol = "ICMP";
            // Always trigger ICMP rule for simulated packets
            if (m_alertCallback) {
                std::cout << "ALERT: Detected simulated ICMP packet from " << sourceIp 
                          << " to " << destIp << std::endl;
                m_alertCallback(1003, "ICMP packet detected (simulated)", packet, header);
                match = true;
            }
        }
        
        return match;
    }
    
    // Real packet processing - extract Ethernet header
    const struct ether_header* etherHeader = (const struct ether_header*)packet;
    
    // Check if it's an IP packet
    if (ntohs(etherHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip* ipHeader = (const struct ip*)(packet + sizeof(struct ether_header));
        
        // Get source and destination IP addresses
        char sourceIp[INET_ADDRSTRLEN];
        char destIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        
        // Determine protocol and check for common attacks
        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: {
                // TCP packet
                const struct tcphdr* tcpHeader = (const struct tcphdr*)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
                uint16_t sourcePort = ntohs(tcpHeader->th_sport);
                uint16_t destPort = ntohs(tcpHeader->th_dport);
                
                // Example: detect SYN flood attempt (simplified)
                if (tcpHeader->th_flags & TH_SYN && !(tcpHeader->th_flags & TH_ACK)) {
                    if (destPort == 80 || destPort == 443) {
                        // In a real implementation, we would track connection attempts over time
                        // For demo purposes, we'll just trigger on SYN packets to common web ports
                        if (m_alertCallback) {
                            m_alertCallback(1000, "Possible SYN scan detected", packet, header);
                            match = true;
                        }
                    }
                }
                
                // Example: detect possible SQL injection attempt (simplified)
                const uint8_t* payload = packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4 + tcpHeader->th_off * 4;
                int payloadLength = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4) - (tcpHeader->th_off * 4);
                
                if (payloadLength > 0) {
                    std::string payloadStr(reinterpret_cast<const char*>(payload), payloadLength);
                    
                    // Very simplified SQL injection detection
                    if (payloadStr.find("SELECT") != std::string::npos && 
                        payloadStr.find("FROM") != std::string::npos &&
                        (payloadStr.find("--") != std::string::npos || 
                         payloadStr.find("'") != std::string::npos)) {
                        
                        if (m_alertCallback) {
                            m_alertCallback(1001, "Possible SQL injection attempt", packet, header);
                            match = true;
                        }
                    }
                }
                break;
            }
            case IPPROTO_UDP: {
                // UDP packet
                const struct udphdr* udpHeader = (const struct udphdr*)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
                uint16_t sourcePort = ntohs(udpHeader->uh_sport);
                uint16_t destPort = ntohs(udpHeader->uh_dport);
                
                // Example: detect DNS amplification attempt (simplified)
                if (sourcePort == 53 && udpHeader->uh_ulen > 512) {
                    if (m_alertCallback) {
                        m_alertCallback(1002, "Possible DNS amplification response", packet, header);
                        match = true;
                    }
                }
                break;
            }
            case IPPROTO_ICMP: {
                // ICMP packet - detect ping flood (simplified)
                if (m_alertCallback) {
                    m_alertCallback(1003, "ICMP packet detected", packet, header);
                    match = true;
                }
                break;
            }
        }
    }
    
    return match;
}

bool RuleEngine::reloadRules() {
    if (!m_initialized) {
        m_lastError = "Rule engine not initialized";
        return false;
    }
    
    // In a real implementation, we would reload the Snort rules
    // For this example, we'll just check if the rules directory is still accessible
    
    if (access(m_rulesDir.c_str(), R_OK) != 0) {
        m_lastError = "Rules directory does not exist or is not readable: " + m_rulesDir;
        return false;
    }
    
    return true;
}

std::string RuleEngine::getLastError() const {
    return m_lastError;
}
