package com.coverity.pie.core;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

public class PolicyConfig {
    private final String name;
    private final PieConfig pieConfig;
    
    public PolicyConfig(String name, PieConfig pieConfig) {
        this.name = name;
        this.pieConfig = pieConfig;
    }
    
    public boolean isEnabled() {
        return getBoolean("isEnabled", true);
    }
    
    public boolean isReportOnlyMode() {
        return getBoolean("isReportOnlyMode", true);
    }
    
    public URL getPolicyFile() {
        String policyFile = getProperty("policyFile");
        if (policyFile != null) {
            try {
                return new URL(policyFile);
            } catch (MalformedURLException e) {
                throw new IllegalStateException("Invalid policy URL: " + policyFile);
            }
        }
        URL resource = this.getClass().getClassLoader().getResource(name + ".policy");
        if (resource != null) {
            return resource;
        }
        String catalinaHome = System.getProperty("catalina.home");
        if (catalinaHome != null) {
            try {
                return new File(catalinaHome + File.separatorChar + "conf" + File.separatorChar + name + ".policy").toURI().toURL();
            } catch (MalformedURLException e) {
                throw new IllegalStateException("Could not build default policy file path.");
            }
        }
        
        // Default to file in the CWD
        try {
            return new File(name + ".policy").toURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    
    public boolean getBoolean(String prop, boolean defaultValue) {
        String v = getProperty(prop);
        if (v == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(v);
    }
    public int getInteger(String prop, int defaultValue) {
        String v = getProperty(prop);
        if (v == null) {
            return defaultValue;
        }
        return Integer.parseInt(v);
    }
    
    
    public String getProperty(String name) {
        return pieConfig.getProperties().getProperty(this.name + "." + name);
    }
    public String getProperty(String name, String defaultValue) {
        return pieConfig.getProperties().getProperty(this.name + "." + name, defaultValue);
    }
}
