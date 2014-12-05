package com.coverity.pie.policy.csp;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import com.coverity.pie.core.PieConfig;

public class CspConfig {

    private boolean enabled;
    private boolean simplePolicy;
    private boolean reportOnlyMode;
    private URL policyPath;
    
    public CspConfig(PieConfig pieConfig) {
        Properties props = pieConfig.getProperties();
        
        enabled = Boolean.parseBoolean(props.getProperty("csp.enabled", "true"));
        simplePolicy = Boolean.parseBoolean(props.getProperty("csp.simplePolicy", "true"));
        reportOnlyMode = Boolean.parseBoolean(props.getProperty("csp.reportOnlyMode", "true"));
        
        String policyPathStr = props.getProperty("csp.policyPath", null);
        if (policyPathStr != null) {
            try {
                policyPath = new File(policyPathStr).toURI().toURL();
            } catch (MalformedURLException e) {
                throw new IllegalStateException(e);
            }
        }

        if (policyPath == null) {
            policyPath = this.getClass().getClassLoader().getResource("cspPolicy.policy");
            if (policyPath == null) {
                // Find a default place to put the policy
                if (System.getProperty("catalina.base") != null) {
                    try {
                        policyPath = new File(System.getProperty("catalina.base") + File.separator + "lib" + File.separator + "cspPolicy.policy").toURI().toURL();
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    try {
                        policyPath = File.createTempFile("cspPolicy", "policy").toURI().toURL();
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isSimplePolicy() {
        return simplePolicy;
    }

    public boolean isReportOnlyMode() {
        return reportOnlyMode;
    }

    public URL getPolicyPath() {
        return policyPath;
    }
}
