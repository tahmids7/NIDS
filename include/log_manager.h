/**
 * @file log_manager.h
 * @brief Log management system
 */

#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <string>
#include <fstream>
#include <memory>
#include <mutex>
#include "alert_system.h"

/**
 * @enum LogLevel
 * @brief Log severity levels
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * @class LogManager
 * @brief Manages logging for the NIDS
 */
class LogManager {
public:
    /**
     * @brief Constructor
     * @param logDir Directory for log files
     * @param alertLogFile Name of alert log file
     * @param systemLogFile Name of system log file
     */
    LogManager(const std::string& logDir, 
              const std::string& alertLogFile = "alerts.log",
              const std::string& systemLogFile = "system.log");
    
    /**
     * @brief Destructor
     */
    ~LogManager();
    
    /**
     * @brief Initialize the log manager
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * @brief Log an alert
     * @param alert Alert to log
     */
    void logAlert(const Alert& alert);
    
    /**
     * @brief Log a system message
     * @param level Log level
     * @param message Message to log
     */
    void log(LogLevel level, const std::string& message);
    
    /**
     * @brief Set minimum log level
     * @param level Minimum level to log
     */
    void setLogLevel(LogLevel level);
    
    /**
     * @brief Get current log level
     * @return Current log level
     */
    LogLevel getLogLevel() const;
    
    /**
     * @brief Get alert log path
     * @return Path to alert log file
     */
    std::string getAlertLogPath() const;
    
    /**
     * @brief Get system log path
     * @return Path to system log file
     */
    std::string getSystemLogPath() const;

private:
    std::string m_logDir;
    std::string m_alertLogFile;
    std::string m_systemLogFile;
    std::string m_alertLogPath;
    std::string m_systemLogPath;
    std::ofstream m_alertLogStream;
    std::ofstream m_systemLogStream;
    LogLevel m_logLevel;
    mutable std::mutex m_alertMutex;
    mutable std::mutex m_systemMutex;
    
    /**
     * @brief Get current timestamp as string
     * @return Current timestamp
     */
    std::string getCurrentTimestamp() const;
    
    /**
     * @brief Convert log level to string
     * @param level Log level
     * @return String representation of log level
     */
    std::string logLevelToString(LogLevel level) const;
};

#endif // LOG_MANAGER_H
