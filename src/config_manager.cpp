/**
 * @file config_manager.cpp
 * @brief Implementation of the configuration manager
 */

#include "config_manager.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <filesystem>

ConfigManager::ConfigManager(const std::string& configPath)
    : m_configPath(configPath), m_loaded(false) {
}

ConfigManager::~ConfigManager() {
}

bool ConfigManager::loadConfig() {
    try {
        // Check if the file exists
        std::ifstream configFile(m_configPath);
        if (!configFile.good()) {
            std::cerr << "Config file does not exist or is not accessible: " << m_configPath << std::endl;
            std::cerr << "Current directory: " << std::filesystem::current_path() << std::endl;
            return false;
        }
        
        // Print first few lines for debugging
        std::string line;
        std::cerr << "First lines of config file:" << std::endl;
        for (int i = 0; i < 5 && std::getline(configFile, line); i++) {
            std::cerr << line << std::endl;
        }
        configFile.close();
        
        // Load configuration from YAML file
        m_config = YAML::LoadFile(m_configPath);
        m_loaded = true;
        return true;
    }
    catch (const YAML::Exception& ex) {
        std::cerr << "Error loading configuration: " << ex.what() << std::endl;
        return false;
    }
    catch (const std::exception& ex) {
        std::cerr << "General error loading configuration: " << ex.what() << std::endl;
        return false;
    }
}

bool ConfigManager::saveConfig() {
    try {
        // Save configuration to YAML file
        std::ofstream file(m_configPath);
        if (!file.is_open()) {
            std::cerr << "Error opening configuration file for writing: " << m_configPath << std::endl;
            return false;
        }
        
        file << m_config;
        file.close();
        return true;
    }
    catch (const std::exception& ex) {
        std::cerr << "Error saving configuration: " << ex.what() << std::endl;
        return false;
    }
}

std::string ConfigManager::getString(const std::string& section, const std::string& key, 
                                   const std::string& defaultValue) const {
    if (!m_loaded || !hasKey(section, key)) {
        return defaultValue;
    }
    
    return m_config[section][key].as<std::string>();
}

int ConfigManager::getInt(const std::string& section, const std::string& key, 
                        int defaultValue) const {
    if (!m_loaded || !hasKey(section, key)) {
        return defaultValue;
    }
    
    return m_config[section][key].as<int>();
}

bool ConfigManager::getBool(const std::string& section, const std::string& key, 
                          bool defaultValue) const {
    if (!m_loaded || !hasKey(section, key)) {
        return defaultValue;
    }
    
    return m_config[section][key].as<bool>();
}

void ConfigManager::setString(const std::string& section, const std::string& key, 
                            const std::string& value) {
    m_config[section][key] = value;
}

void ConfigManager::setInt(const std::string& section, const std::string& key, int value) {
    m_config[section][key] = value;
}

void ConfigManager::setBool(const std::string& section, const std::string& key, bool value) {
    m_config[section][key] = value;
}

bool ConfigManager::hasKey(const std::string& section, const std::string& key) const {
    return m_config[section] && m_config[section][key];
}
