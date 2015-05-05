package com.coverity.security.pie.policy.securitymanager;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;

import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.util.IOUtil;

/**
 * An implementation of the Java SecurityManager Policy class, which delegates policy decisions to the PIE policy.
 * Whitelists permissions for PIE classes based on their certificate signature.
 */
public class DynamicJavaPolicy extends Policy {
    
    private final Collection<Policy> parentPolicies;
    private final PublicKey coverityPublicKey;
    
    private final SecurityManagerPolicy policy;
    private final PolicyConfig policyConfig;
    
    public DynamicJavaPolicy(Policy parentPolicy, SecurityManagerPolicy policy, PolicyConfig policyConfig) {
        this.parentPolicies = new ArrayList<Policy>();
        if (parentPolicy != null) {
            this.parentPolicies.add(parentPolicy);
        }
        
        this.policy = policy;
        this.policyConfig = policyConfig;

        try {
            coverityPublicKey = loadPublicX509("/coverity.crt").getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    private Certificate loadPublicX509(String fileName) throws GeneralSecurityException, IOException {
        InputStream is = null;
        Certificate crt = null;
        try {
            is = this.getClass().getResourceAsStream(fileName);
            if (is == null) {
                throw new IllegalArgumentException("Could not find resource: " + fileName);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            crt = cf.generateCertificate(is);
            is.close();
            return crt;
        } catch (IOException e) {
            IOUtil.closeSilently(is);
            throw e;
        }
    }
    
    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {
        try {
            // Blacklisted
            if (permission.getName().equals("setPolicy") || permission.getName().equals("setSecurityManager")) {
                return false;
            }

            for (Policy parentPolicy : parentPolicies) {
                if (parentPolicy.implies(domain, permission)) {
                    return true;
                }
            }

            String callingClassName = Thread.currentThread().getStackTrace()[2].getClassName();
            if (callingClassName.startsWith("com.coverity.security.pie.") && domain.getCodeSource() != null) {
                Certificate[] certificates = domain.getCodeSource().getCertificates();
                if (certificates != null && certificates.length > 0) {
                    try {
                        certificates[0].verify(coverityPublicKey);
                        return true;
                    } catch (InvalidKeyException e) {
                        // Do nothing
                    } catch (CertificateException e) {
                        // Do nothing
                    } catch (NoSuchAlgorithmException e) {
                        // Do nothing
                    } catch (NoSuchProviderException e) {
                        // Do nothing
                    } catch (SignatureException e) {
                        // Do nothing
                    }
                }
            }

            if (policy.implies(domain.getCodeSource(), permission)) {
                return true;
            }
            policy.logViolation(domain.getCodeSource(), permission);
            
            if (policyConfig.isReportOnlyMode()) {
                return true;
            }
            return false;
        } catch (RuntimeException e) {
            e.printStackTrace();
            throw e;
        }
    }
     
    
    @Override
    public void refresh() {
        for (Policy parentPolicy : parentPolicies) {
            parentPolicy.refresh();
        }
    }
}
