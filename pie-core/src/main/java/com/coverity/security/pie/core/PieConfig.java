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
    
    private boolean enabled;
    private boolean regenerateOnShutdown;
    private boolean adminInterfaceEnabled;
    
    public PieConfig() {
        File propFile = new File("pieConfig.properties");
        if (propFile.exists()) {
            try {
                init(propFile.toURI().toURL());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        } else {
            init(this.getClass().getClassLoader().getResource("pieConfig.properties"));
        }
    }
    public PieConfig(URL propertiesUrl) {
        init(propertiesUrl);
    }
    private void init(URL propertiesUrl) {
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
        
        enabled = Boolean.parseBoolean(properties.getProperty("pie.enabled", "true"));
        regenerateOnShutdown = Boolean.parseBoolean(properties.getProperty("pie.regenerateOnShutdown", "true"));
        adminInterfaceEnabled = Boolean.parseBoolean(properties.getProperty("pie.admininterface.enabled", "false"));
    }
    
    
    public Properties getProperties() {
        return properties;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isRegenerateOnShutdown() {
        return regenerateOnShutdown;
    }

    public boolean isAdminInterfaceEnabled() {
        return adminInterfaceEnabled;
    }
}
