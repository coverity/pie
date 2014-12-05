package com.coverity.pie.policy.securitymanager;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.URIParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;

import com.coverity.pie.policy.securitymanager.SecurityManagerPolicyBuilder;
import com.coverity.pie.util.IOUtil;

public class DynamicJavaPolicy extends Policy {
    
    private final Collection<Policy> parentPolicies;
    private final PublicKey coverityPublicKey;
    private final SecurityManagerPolicyBuilder policyBuilder;
    
    public DynamicJavaPolicy(Policy parentPolicy, SecurityManagerPolicyBuilder policyBuilder) {
        this.parentPolicies = new ArrayList<Policy>();
        if (parentPolicy != null) {
            this.parentPolicies.add(parentPolicy);
        }
        this.policyBuilder = policyBuilder;
        if (policyBuilder.getConfig().getPolicyPath() != null) {
            try {
                this.parentPolicies.add(Policy.getInstance("JavaPolicy", new URIParameter(policyBuilder.getConfig().getPolicyPath().toURI())));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
        
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
        // Blacklisted
        if (permission.getName().equals("setPolicy") || permission.getName().equals("setSecurityManager")) {
            return false;
        }
        
        boolean allowed;
        for (Policy parentPolicy : parentPolicies) {
            allowed = parentPolicy.implies(domain, permission);
            if (allowed) {
                return true;
            }
        }
        
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        /*
            java.lang.Thread.getStackTrace(Thread.java:1552)
            com.coverity.pie.PiePolicy.implies(PiePolicy.java:33)
            java.security.ProtectionDomain.implies(ProtectionDomain.java:272)
            java.security.AccessControlContext.checkPermission(AccessControlContext.java:435)
            java.security.AccessController.checkPermission(AccessController.java:884)
            java.lang.SecurityManager.checkPermission(SecurityManager.java:549)
            java.lang.SecurityManager.checkRead(SecurityManager.java:888)
            java.io.File.exists(File.java:814)
            org.apache.naming.resources.FileDirContext.file(FileDirContext.java:768)
            org.apache.naming.resources.FileDirContext.doLookup(FileDirContext.java:198)
            org.apache.naming.resources.BaseDirContext.lookup(BaseDirContext.java:483)
            org.apache.naming.resources.ProxyDirContext.lookup(ProxyDirContext.java:308)
            org.apache.catalina.loader.WebappClassLoader.findResourceInternal(WebappClassLoader.java:2993)
            org.apache.catalina.loader.WebappClassLoader.findClassInternal(WebappClassLoader.java:2853)
            org.apache.catalina.loader.WebappClassLoader.findClass(WebappClassLoader.java:1174)
            org.apache.catalina.loader.WebappClassLoader.loadClass(WebappClassLoader.java:1669)
            org.apache.catalina.loader.WebappClassLoader.loadClass(WebappClassLoader.java:1547)
            org.springframework.util.StringUtils.collectionToDelimitedString(StringUtils.java:1047)
            org.springframework.util.StringUtils.collectionToDelimitedString(StringUtils.java:1069)
            org.springframework.util.StringUtils.cleanPath(StringUtils.java:632)
            org.springframework.core.io.ClassPathResource.<init>(ClassPathResource.java:94)
            org.springframework.web.context.ContextLoader.<clinit>(ContextLoader.java:135)
            sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
            sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
            sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
            java.lang.reflect.Constructor.newInstance(Constructor.java:408)
            java.lang.Class.newInstance(Class.java:433)
            org.apache.catalina.core.DefaultInstanceManager.newInstance(DefaultInstanceManager.java:143)
            org.apache.catalina.core.StandardContext.listenerStart(StandardContext.java:4854)
            org.apache.catalina.core.StandardContext.startInternal(StandardContext.java:5434)
            org.apache.catalina.util.LifecycleBase.start(LifecycleBase.java:150)
            org.apache.catalina.core.ContainerBase.addChildInternal(ContainerBase.java:901)
            org.apache.catalina.core.ContainerBase.addChild(ContainerBase.java:877)
            org.apache.catalina.core.StandardHost.addChild(StandardHost.java:633)
            org.apache.catalina.startup.HostConfig.deployWAR(HostConfig.java:983)
            org.apache.catalina.startup.HostConfig$DeployWar.run(HostConfig.java:1660)
            java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:511)
            java.util.concurrent.FutureTask.run(FutureTask.java:266)
            java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1142)
            java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:617)
            java.lang.Thread.run(Thread.java:745)
         */
        
        String callingClassName = null;
        for (int i = 2; i < stackTrace.length; i++) {
            String className = stackTrace[i].getClassName();
            if (!className.startsWith("java.")
                    && !className.startsWith("sun.")) {
                callingClassName = className;
                break;
            }
        }
        if (callingClassName.startsWith("com.coverity.pie.")) {
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
        
        policyBuilder.registerPolicyViolation(stackTrace, domain.getCodeSource().getLocation(), permission);
        
        if (policyBuilder.getConfig().isReportOnlyMode()) {
            return true;
        }
        return false;
    }
     
    
    @Override
    public void refresh() {
        for (Policy parentPolicy : parentPolicies) {
            parentPolicy.refresh();
        }
    }
}
