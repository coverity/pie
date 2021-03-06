package com.coverity.security.pie.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import com.coverity.security.pie.util.IOUtil;

/**
 * Configuration for PIE. This abstracts reading in the pieConfig.properties file and returning configuration
 * directives.
 */
public class PieConfig {

    private final Properties properties = new Properties();

    public PieConfig() {
        loadProps(this.getClass().getClassLoader().getResource("pieConfig.default.properties"));
        File propFile = new File("pieConfig.properties");
        if (propFile.exists()) {
            try {
                loadProps(propFile.toURI().toURL());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        } else {
            loadProps(this.getClass().getClassLoader().getResource("pieConfig.properties"));
        }
    }
    public PieConfig(URL propertiesUrl) {
        loadProps(this.getClass().getClassLoader().getResource("pieConfig.default.properties"));
        loadProps(propertiesUrl);
    }
    private void loadProps(URL propertiesUrl) {
        if (propertiesUrl != null) {
            InputStream is = null;
            try {
                is = propertiesUrl.openStream();
                if (is != null) {
                    properties.load(is);
                    is.close();
                }
            } catch (IOException e) {
                IOUtil.closeSilently(is);
                throw new RuntimeException(e);
            }
        }

    }

    public Properties getProperties() {
        return properties;
    }

    private boolean getBoolean(String prop, boolean defaultValue) {
        String v = getProperty(prop);
        if (v == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(v);
    }

    private String getProperty(String name) {
        return properties.getProperty("pie." + name);
    }

    public boolean isEnabled() {
        return getBoolean("enabled", true);
    }

    public boolean isRegenerateOnShutdown() {
        return getBoolean("regenerateOnShutdown", true);
    }

    public boolean isAdminInterfaceEnabled() {
        return getBoolean("admininterface.enabled", false);
    }

    public boolean isLoggingEnabled() { return getBoolean("loggingEnabled", false); }

    public String getLogPath() { return getProperty("logPath"); }
}
