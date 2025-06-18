/**
 * @file packet_capture.h
 * @brief Packet capture functionality using libpcap
 */

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <string>
#include <functional>
#include <pcap.h>

/**
 * @class PacketCapture
 * @brief Handles network packet capture using libpcap
 */
class PacketCapture {
public:
    /**
     * @brief Callback function type for packet processing
     */
    using PacketCallback = std::function<void(const uint8_t*, const struct pcap_pkthdr*)>;
    
    /**
     * @brief Constructor
     * @param device Network interface to capture from
     * @param promiscuous Whether to use promiscuous mode
     * @param snaplen Maximum bytes to capture per packet
     * @param timeoutMs Timeout in milliseconds
     */
    PacketCapture(const std::string& device, bool promiscuous = true, 
                 int snaplen = 65535, int timeoutMs = 1000);
    
    /**
     * @brief Destructor
     */
    ~PacketCapture();
    
    /**
     * @brief Initialize the packet capture
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * @brief Set BPF filter for packet capture
     * @param filterExpr Filter expression
     * @return True if filter was set successfully, false otherwise
     */
    bool setFilter(const std::string& filterExpr);
    
    /**
     * @brief Start packet capture
     * @param callback Function to call for each captured packet
     * @return True if capture started successfully, false otherwise
     */
    bool startCapture(PacketCallback callback);
    
    /**
     * @brief Stop packet capture
     */
    void stopCapture();
    
    /**
     * @brief Check if capture is running
     * @return True if running, false otherwise
     */
    bool isRunning() const;
    
    /**
     * @brief Get error message if an operation failed
     * @return Error message
     */
    std::string getLastError() const;

private:
    std::string m_device;
    bool m_promiscuous;
    int m_snaplen;
    int m_timeoutMs;
    pcap_t* m_pcapHandle;
    bool m_running;
    bool m_simulationMode = false;
    std::string m_lastError;
    
    /**
     * @brief Static callback function for libpcap
     */
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet);
    
    /**
     * @brief Thread function for packet capture
     */
    void captureThread(PacketCallback callback);
    
    /**
     * @brief Create simulated network traffic for testing
     * @param buffer Buffer to write the packet to
     * @param length Reference to store the packet length
     * @param packetType Type of packet to create (0=TCP, 1=UDP, 2=ICMP)
     */
    void createSimulatedTraffic(uint8_t* buffer, int& length, int packetType);
    
    /**
     * @brief Thread function for simulated packet generation
     */
    void simulationThread(PacketCallback callback);
};

#endif // PACKET_CAPTURE_H
