/**
 * @file main.cpp
 * @brief Main entry point for the Network Intrusion Detection System
 */

#include <iostream>
#include <string>
#include <csignal>
#include <cstring>
#include <thread>
#include <chrono>
#include <filesystem>
#include "nids.h"

// Global NIDS instance for signal handling
static NIDS* g_nids = nullptr;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived shutdown signal. Stopping NIDS..." << std::endl;
        if (g_nids) {
            g_nids->stop();
        }
    }
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config <file>     Path to configuration file (default: /etc/nids/nids_config.yaml)" << std::endl;
    std::cout << "  -h, --help              Display this help message and exit" << std::endl;
    std::cout << "  -v, --version           Display version information and exit" << std::endl;
}

void printVersion() {
    std::cout << "Network Intrusion Detection System v1.0.0" << std::endl;
    std::cout << "Built with C++ and Snort integration" << std::endl;
}

int main(int argc, char* argv[]) {
    // Default configuration path
    std::string configPath = "config/nids_config.yaml";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printVersion();
            return 0;
        }
        else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            configPath = argv[i + 1];
            i++; // Skip the next argument
        }
        else {
            std::cerr << "Unknown option: " << argv[i] << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Check if configuration file exists
    if (!std::filesystem::exists(configPath)) {
        std::cerr << "Configuration file not found: " << configPath << std::endl;
        std::cerr << "Using default configuration" << std::endl;
    }
    
    try {
        // Register signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);
        
        // Create NIDS instance
        std::cout << "Loading configuration from: " << configPath << std::endl;
        std::cout << "Current working directory: " << std::filesystem::current_path() << std::endl;
        
        NIDS nids(configPath);
        g_nids = &nids;
        
        // Initialize NIDS
        std::cout << "Initializing NIDS..." << std::endl;
        if (!nids.initialize()) {
            std::cerr << "Failed to initialize NIDS" << std::endl;
            return 1;
        }
        
        // Start NIDS
        std::cout << "Starting NIDS..." << std::endl;
        if (!nids.start()) {
            std::cerr << "Failed to start NIDS" << std::endl;
            return 1;
        }
        
        std::cout << "NIDS is running. Press Ctrl+C to stop." << std::endl;
        
        // Main loop to keep the program running
        while (nids.isRunning()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        std::cout << "NIDS stopped" << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
    
    return 0;
}
