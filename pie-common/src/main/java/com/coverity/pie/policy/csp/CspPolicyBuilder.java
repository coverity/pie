package com.coverity.pie.policy.csp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.PolicyBuilder;

public class CspPolicyBuilder implements PolicyBuilder {

    private final Collection<CspViolation> violations = new HashSet<CspViolation>();
    
    private CspConfig cspConfig;
    
    @Override
    public String getName() {
        return "CSP";
    }
    
    @Override
    public void init(PieConfig pieConfig) {
        cspConfig = new CspConfig(pieConfig);
    }

    @Override
    public boolean isEnabled() {
        return cspConfig.isEnabled();
    }

    @Override
    public void savePolicy() {
        try {
            CspPolicy policy = getPolicy();
            for (CspViolation cspViolation : violations) {
                
                String hostSource;
                if (cspViolation.getBlockedUri().charAt(0) == '\'') {
                    hostSource = cspViolation.getBlockedUri();
                } else {
                    URI blockedUri;
                    try {
                        blockedUri = new URI(cspViolation.getBlockedUri());
                    } catch (URISyntaxException e) {
                        throw new IllegalArgumentException("Invalid syntax in violation", e);
                    }
                    StringBuilder hostname = new StringBuilder();
                    if (blockedUri.getScheme() != null) {
                        hostname.append(blockedUri.getScheme()).append("://");
                    }
                    hostname.append(blockedUri.getHost());
                    if (blockedUri.getPort() != -1) {
                        hostname.append(":").append(blockedUri.getPort());
                    }
                    hostSource = hostname.toString();
                }
                
                Map<String, List<String>> directives = new HashMap<String, List<String>>();
                directives.put(cspViolation.getViolatedDirectiveName(), Arrays.asList(hostSource.toString()));
                
                policy.getPolicyEntries().add(new CspPolicyEntry(cspViolation.getDocumentUri(), directives));
            }
            policy = CspPolicySimplifier.simplifyPolicy(policy);
            CspPolicyFileUtil.writeFile(cspConfig.getPolicyPath(), policy);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getPolicyViolations() {
        StringBuilder sb = new StringBuilder();
        for (CspViolation cspViolation : violations) {
            sb.append(cspViolation.getDocumentUri()).append("\t")
                .append(cspViolation.getBlockedUri()).append("\t")
                .append(cspViolation.getViolatedDirectiveName()).append("\n");
        }
        return sb.toString();
    }

    @Override
    public void registerPolicyViolations(String policyViolations) {
        String[] lines = policyViolations.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.equals("")) {
                continue;
            }
            String[] fields = line.split("\t");
            violations.add(new CspViolation(fields[0], fields[1], fields[2]));
        }
    }
    
    public void registerPolicyViolation(CspViolation cspViolation) {
        this.violations.add(cspViolation);
    }
    
    public CspConfig getConfig() {
        return this.cspConfig;
    }
    
    public CspPolicy getPolicy() throws IOException {
        return CspPolicyFileUtil.parseFile(cspConfig.getPolicyPath());
    }
}
