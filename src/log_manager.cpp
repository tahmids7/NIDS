/**
 * @file log_manager.cpp
 * @brief Implementation of the log manager
 */

#include "log_manager.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace fs = std::filesystem;

LogManager::LogManager(const std::string& logDir, const std::string& alertLogFile, const std::string& systemLogFile)
    : m_logDir(logDir), m_alertLogFile(alertLogFile), m_systemLogFile(systemLogFile), m_logLevel(LogLevel::INFO) {
    
    // Set log file paths
    m_alertLogPath = m_logDir + "/" + m_alertLogFile;
    m_systemLogPath = m_logDir + "/" + m_systemLogFile;
}

LogManager::~LogManager() {
    // Close log streams
    if (m_alertLogStream.is_open()) {
        m_alertLogStream.close();
    }
    
    if (m_systemLogStream.is_open()) {
        m_systemLogStream.close();
    }
}

bool LogManager::initialize() {
    try {
        // Create log directory if it doesn't exist
        if (!fs::exists(m_logDir)) {
            if (!fs::create_directories(m_logDir)) {
                std::cerr << "Failed to create log directory: " << m_logDir << std::endl;
                return false;
            }
        }
        
        // Open log files
        m_alertLogStream.open(m_alertLogPath, std::ios::app);
        if (!m_alertLogStream.is_open()) {
            std::cerr << "Failed to open alert log file: " << m_alertLogPath << std::endl;
            return false;
        }
        
        m_systemLogStream.open(m_systemLogPath, std::ios::app);
        if (!m_systemLogStream.is_open()) {
            std::cerr << "Failed to open system log file: " << m_systemLogPath << std::endl;
            m_alertLogStream.close();
            return false;
        }
        
        // Log initialization
        log(LogLevel::INFO, "Log system initialized");
        
        return true;
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception during log initialization: " << ex.what() << std::endl;
        return false;
    }
}

void LogManager::logAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(m_alertMutex);
    
    if (!m_alertLogStream.is_open()) {
        return;
    }
    
    // Format alert for logging
    m_alertLogStream << "[" << alert.timestamp << "] "
                    << "ALERT #" << alert.id << " (SID: " << alert.ruleId << "): " 
                    << alert.message << " "
                    << "(" << alert.sourceIp << ":" << alert.sourcePort << " -> " 
                    << alert.destIp << ":" << alert.destPort << ") "
                    << "Protocol: " << alert.protocol << " "
                    << "Severity: " << alert.severity << std::endl;
    
    m_alertLogStream.flush();
}

void LogManager::log(LogLevel level, const std::string& message) {
    // Skip if level is below current log level
    if (level < m_logLevel) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_systemMutex);
    
    if (!m_systemLogStream.is_open()) {
        return;
    }
    
    // Get current timestamp
    std::string timestamp = getCurrentTimestamp();
    
    // Log to system log file
    m_systemLogStream << "[" << timestamp << "] [" << logLevelToString(level) << "] " 
                     << message << std::endl;
    
    m_systemLogStream.flush();
}

void LogManager::setLogLevel(LogLevel level) {
    m_logLevel = level;
}

LogLevel LogManager::getLogLevel() const {
    return m_logLevel;
}

std::string LogManager::getAlertLogPath() const {
    return m_alertLogPath;
}

std::string LogManager::getSystemLogPath() const {
    return m_systemLogPath;
}

std::string LogManager::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string LogManager::logLevelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}
