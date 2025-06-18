/**
 * @file nids.cpp
 * @brief Implementation of the main NIDS class
 */

#include "nids.h"
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <fstream>  // Added for std::ifstream
#include <functional>
#include <pcap/pcap.h>  // For pcap_pkthdr
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

NIDS::NIDS(const std::string& configPath)
    : m_initialized(false), m_running(false) {
    // Create config manager
    try {
        m_configManager = std::make_unique<ConfigManager>(configPath);
        
        if (!m_configManager->loadConfig()) {
            throw std::runtime_error("Failed to load configuration from " + configPath);
        }
    } catch (const std::exception& ex) {
        std::cerr << "Exception in ConfigManager: " << ex.what() << std::endl;
        throw;
    }
}

NIDS::~NIDS() {
    if (m_running) {
        stop();
    }
}

bool NIDS::initialize() {
    if (m_initialized) {
        return true;
    }
    
    try {
        // Initialize log manager
        std::string logDir = m_configManager->getString("logging", "log_directory", "/var/log/nids");
        std::cout << "Using log directory: " << logDir << std::endl;
        
        try {
            m_logManager = std::make_unique<LogManager>(logDir);
            
            if (!m_logManager->initialize()) {
                std::cerr << "Failed to initialize log manager" << std::endl;
                return false;
            }
            
            std::cout << "Log manager initialized successfully" << std::endl;
            
            // Log initialization
            m_logManager->log(LogLevel::INFO, "NIDS initializing...");
        } catch (const std::exception& ex) {
            std::cerr << "Exception in log manager initialization: " << ex.what() << std::endl;
            return false;
        }
        
        // Initialize alert system
        std::cout << "Initializing alert system..." << std::endl;
        try {
            m_alertSystem = std::make_unique<AlertSystem>();
            
            if (!m_alertSystem->initialize()) {
                m_logManager->log(LogLevel::ERROR, "Failed to initialize alert system");
                std::cerr << "Failed to initialize alert system" << std::endl;
                return false;
            }
            std::cout << "Alert system initialized successfully" << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Exception in alert system initialization: " << ex.what() << std::endl;
            return false;
        }
        
        // Register alert callback to log alerts
        m_alertSystem->registerCallback([this](const Alert& alert) {
            m_logManager->logAlert(alert);
            m_logManager->log(LogLevel::INFO, "Alert generated: " + alert.message);
        });
        
        // Initialize rule engine
        std::cout << "Initializing rule engine..." << std::endl;
        try {
            std::string rulesDir = m_configManager->getString("rules", "rules_directory", "/etc/snort/rules");
            std::string snortConfig = m_configManager->getString("snort", "config_path", "/etc/snort/snort.conf");
            
            std::cout << "Rules directory: " << rulesDir << std::endl;
            std::cout << "Snort config path: " << snortConfig << std::endl;
            
            // Check if rules directory exists in the current location
            std::ifstream testFile(rulesDir + "/local.rules");
            if (!testFile.good()) {
                std::cerr << "Rules directory does not exist or local.rules not found!" << std::endl;
                // Try to find it relative to the build directory
                rulesDir = "../" + rulesDir;
                std::cout << "Trying alternate path: " << rulesDir << std::endl;
                testFile = std::ifstream(rulesDir + "/local.rules");
                if (!testFile.good()) {
                    std::cerr << "Alternate rules directory path also does not exist!" << std::endl;
                }
            }
            if (testFile.is_open()) {
                testFile.close();
            }
            
            m_ruleEngine = std::make_unique<RuleEngine>(rulesDir, snortConfig);
            
            if (!m_ruleEngine->initialize()) {
                std::cerr << "Failed to initialize rule engine: " << m_ruleEngine->getLastError() << std::endl;
                m_logManager->log(LogLevel::ERROR, "Failed to initialize rule engine: " + m_ruleEngine->getLastError());
                return false;
            }
            
            std::cout << "Rule engine initialized successfully" << std::endl;
            
            // Set rule engine alert callback
            m_ruleEngine->setAlertCallback([this](int sid, const std::string& msg, const uint8_t* packet, const pcap_pkthdr* header) {
                // Default values
                std::string sourceIp = "0.0.0.0";
                std::string destIp = "0.0.0.0";
                int sourcePort = 0;
                int destPort = 0;
                std::string protocol = "UNKNOWN";
                
                // Try to extract information from the packet
                if (packet != nullptr && header != nullptr) {
                    std::string packetData(reinterpret_cast<const char*>(packet), header->caplen < 200 ? header->caplen : 200);
                    
                    // Check if this is a simulated packet
                    if (packetData.find("SIMULATED PACKET") == 0) {
                        // Extract information from the simulated packet format
                        if (packetData.find("TYPE=TCP") != std::string::npos) {
                            protocol = "TCP";
                        } else if (packetData.find("TYPE=UDP") != std::string::npos) {
                            protocol = "UDP";
                        } else if (packetData.find("TYPE=ICMP") != std::string::npos) {
                            protocol = "ICMP";
                        }
                        
                        // Extract source IP and port if present
                        size_t srcPos = packetData.find("SRC=");
                        if (srcPos != std::string::npos) {
                            size_t srcEnd = packetData.find(" ", srcPos);
                            if (srcEnd != std::string::npos) {
                                std::string srcInfo = packetData.substr(srcPos + 4, srcEnd - (srcPos + 4));
                                size_t colonPos = srcInfo.find(":");
                                if (colonPos != std::string::npos) {
                                    sourceIp = srcInfo.substr(0, colonPos);
                                    try {
                                        sourcePort = std::stoi(srcInfo.substr(colonPos + 1));
                                    } catch (const std::exception& e) {
                                        // Handle conversion error
                                        sourcePort = 0;
                                    }
                                } else {
                                    sourceIp = srcInfo;
                                }
                            }
                        }
                        
                        // Extract destination IP and port if present
                        size_t dstPos = packetData.find("DST=");
                        if (dstPos != std::string::npos) {
                            size_t dstEnd = packetData.find(" ", dstPos);
                            if (dstEnd != std::string::npos) {
                                std::string dstInfo = packetData.substr(dstPos + 4, dstEnd - (dstPos + 4));
                                size_t colonPos = dstInfo.find(":");
                                if (colonPos != std::string::npos) {
                                    destIp = dstInfo.substr(0, colonPos);
                                    try {
                                        destPort = std::stoi(dstInfo.substr(colonPos + 1));
                                    } catch (const std::exception& e) {
                                        // Handle conversion error
                                        destPort = 0;
                                    }
                                } else {
                                    destIp = dstInfo;
                                }
                            }
                        }
                    }
                    else {
                        // For real packets, extract information from packet headers
                        // This would be more complex in a production system
                        const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
                        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
                            const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
                            char src_ip[INET_ADDRSTRLEN];
                            char dst_ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
                            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
                            sourceIp = src_ip;
                            destIp = dst_ip;
                            
                            switch (ip_hdr->ip_p) {
                                case IPPROTO_TCP: {
                                    protocol = "TCP";
                                    const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(
                                        packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
                                    sourcePort = ntohs(tcp->th_sport);
                                    destPort = ntohs(tcp->th_dport);
                                    break;
                                }
                                case IPPROTO_UDP: {
                                    protocol = "UDP";
                                    const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(
                                        packet + sizeof(struct ether_header) + (ip_hdr->ip_hl * 4));
                                    sourcePort = ntohs(udp->uh_sport);
                                    destPort = ntohs(udp->uh_dport);
                                    break;
                                }
                                case IPPROTO_ICMP: {
                                    protocol = "ICMP";
                                    break;
                                }
                                default:
                                    protocol = "IP";
                                    break;
                            }
                        }
                    }
                }
                
                // Generate alert with the extracted information
                m_alertSystem->generateAlert(sid, msg, sourceIp, destIp, sourcePort, destPort, protocol, 2);
            });
        } catch (const std::exception& ex) {
            std::cerr << "Exception in rule engine initialization: " << ex.what() << std::endl;
            return false;
        }
        
        // Initialize packet capture
        std::cout << "Initializing packet capture..." << std::endl;
        try {
            std::string device = m_configManager->getString("capture", "interface", "eth0");
            bool promiscuous = m_configManager->getBool("capture", "promiscuous", true);
            int snaplen = m_configManager->getInt("capture", "snaplen", 65535);
            int timeout = m_configManager->getInt("capture", "timeout_ms", 1000);
            
            std::cout << "Capture interface: " << device << std::endl;
            std::cout << "Promiscuous mode: " << (promiscuous ? "true" : "false") << std::endl;
            
            m_packetCapture = std::make_unique<PacketCapture>(device, promiscuous, snaplen, timeout);
            
            if (!m_packetCapture->initialize()) {
                std::cerr << "Failed to initialize packet capture: " << m_packetCapture->getLastError() << std::endl;
                m_logManager->log(LogLevel::ERROR, "Failed to initialize packet capture: " + m_packetCapture->getLastError());
                return false;
            }
            
            std::cout << "Packet capture initialized successfully" << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Exception in packet capture initialization: " << ex.what() << std::endl;
            return false;
        }
        
        // Set capture filter if configured
        std::string filter = m_configManager->getString("capture", "filter", "");
        if (!filter.empty()) {
            if (!m_packetCapture->setFilter(filter)) {
                m_logManager->log(LogLevel::ERROR, "Failed to set capture filter: " + m_packetCapture->getLastError());
                return false;
            }
        }
        
        m_initialized = true;
        m_logManager->log(LogLevel::INFO, "NIDS initialization complete");
        return true;
        
    } catch (const std::exception& ex) {
        std::cerr << "Error during NIDS initialization: " << ex.what() << std::endl;
        if (m_logManager) {
            m_logManager->log(LogLevel::ERROR, std::string("Error during NIDS initialization: ") + ex.what());
        }
        return false;
    }
}

bool NIDS::start() {
    if (!m_initialized) {
        if (!initialize()) {
            return false;
        }
    }
    
    if (m_running) {
        m_logManager->log(LogLevel::WARNING, "NIDS is already running");
        return true;
    }
    
    // Set up packet capture callback
    auto callback = [this](const uint8_t* packet, const struct pcap_pkthdr* header) {
        processPacket(packet, header);
    };
    
    // Start packet capture
    if (!m_packetCapture->startCapture(callback)) {
        m_logManager->log(LogLevel::ERROR, "Failed to start packet capture: " + m_packetCapture->getLastError());
        return false;
    }
    
    m_running = true;
    m_logManager->log(LogLevel::INFO, "NIDS started");
    return true;
}

void NIDS::stop() {
    if (!m_running) {
        m_logManager->log(LogLevel::WARNING, "NIDS is not running");
        return;
    }
    
    m_packetCapture->stopCapture();
    m_running = false;
    m_logManager->log(LogLevel::INFO, "NIDS stopped");
}

bool NIDS::isRunning() const {
    return m_running;
}

std::string NIDS::getStatus() const {
    std::string status;
    
    if (!m_initialized) {
        status = "Not initialized";
    } else if (!m_running) {
        status = "Initialized but not running";
    } else {
        status = "Running";
    }
    
    return status;
}

void NIDS::processPacket(const uint8_t* packet, const struct pcap_pkthdr* header) {
    // Process the packet through the rule engine
    m_ruleEngine->processPacket(packet, header);
}
