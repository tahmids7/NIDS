/**
 * @file config_manager.h
 * @brief Configuration management system
 */

#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <map>
#include <yaml-cpp/yaml.h>

/**
 * @class ConfigManager
 * @brief Manages configuration settings for the NIDS
 */
class ConfigManager {
public:
    /**
     * @brief Constructor
     * @param configPath Path to configuration file
     */
    ConfigManager(const std::string& configPath);
    
    /**
     * @brief Destructor
     */
    ~ConfigManager();
    
    /**
     * @brief Load configuration from file
     * @return True if loading succeeded, false otherwise
     */
    bool loadConfig();
    
    /**
     * @brief Save configuration to file
     * @return True if saving succeeded, false otherwise
     */
    bool saveConfig();
    
    /**
     * @brief Get a string configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param defaultValue Default value if key not found
     * @return Configuration value
     */
    std::string getString(const std::string& section, const std::string& key, 
                         const std::string& defaultValue = "") const;
    
    /**
     * @brief Get an integer configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param defaultValue Default value if key not found
     * @return Configuration value
     */
    int getInt(const std::string& section, const std::string& key, 
              int defaultValue = 0) const;
    
    /**
     * @brief Get a boolean configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param defaultValue Default value if key not found
     * @return Configuration value
     */
    bool getBool(const std::string& section, const std::string& key, 
                bool defaultValue = false) const;
    
    /**
     * @brief Set a string configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param value Configuration value
     */
    void setString(const std::string& section, const std::string& key, 
                  const std::string& value);
    
    /**
     * @brief Set an integer configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param value Configuration value
     */
    void setInt(const std::string& section, const std::string& key, int value);
    
    /**
     * @brief Set a boolean configuration value
     * @param section Configuration section
     * @param key Configuration key
     * @param value Configuration value
     */
    void setBool(const std::string& section, const std::string& key, bool value);

private:
    std::string m_configPath;
    YAML::Node m_config;
    bool m_loaded;
    
    /**
     * @brief Check if a section and key exist in configuration
     * @param section Configuration section
     * @param key Configuration key
     * @return True if section and key exist, false otherwise
     */
    bool hasKey(const std::string& section, const std::string& key) const;
};

#endif // CONFIG_MANAGER_H
