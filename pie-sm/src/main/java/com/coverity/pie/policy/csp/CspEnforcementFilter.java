package com.coverity.pie.policy.csp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;
import org.json.JSONObject;

import com.coverity.pie.util.IOUtil;

public class CspEnforcementFilter implements Filter {

    private static final String REPORT_URI = "/a379568856ef23aPIE19bc95ce4e2f7fd2b";
    
    private final CspPolicyBuilder policyBuilder;
    private CspPolicy policy;
    
    public CspEnforcementFilter(CspPolicyBuilder policyBuilder) {
        this.policyBuilder = policyBuilder;
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        if (request == null || response == null || !(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;
        
        if (REPORT_URI.equals(httpServletRequest.getRequestURI())) {
            JSONObject json = new JSONObject(IOUtil.toString(httpServletRequest.getInputStream()));
            json = json.getJSONObject("csp-report");
            try {
                String violatedDirectiveName = json.getString("violated-directive").split(" ")[0];
                URI documentUri = new URI(json.getString("document-uri"));
                String blocked = json.getString("blocked-uri");
                // Firefox seems to report 'unsafe-inline' as self (no quotes) 
                if (blocked.equals("self") &&
                        (violatedDirectiveName.equals("script-src")
                        || violatedDirectiveName.equals("style-src"))) {
                    blocked = "'unsafe-inline'";
                }
                if (blocked.charAt(0) != '\'') {
                    if (getHostPart(documentUri).equals(getHostPart(new URI(blocked)))) {
                        blocked = "'self'";
                    }
                }
                
                policyBuilder.registerPolicyViolation(new CspViolation(
                        documentUri.getPath(),
                        blocked,
                        violatedDirectiveName
                        ));
            } catch (JSONException | URISyntaxException e) {
                throw new IllegalArgumentException("Invalid request", e);
            }
            return;
        }
        
        if (policy != null) {
            
            String policyStr = policy.getPolicyForUri(httpServletRequest.getRequestURI());
            policyStr += "; report-uri " + REPORT_URI;
            
            if (policyBuilder.getConfig().isReportOnlyMode()) {
                httpServletResponse.addHeader("Content-Security-Policy-Report-Only", policyStr);
            } else {
                httpServletResponse.addHeader("Content-Security-Policy", policyStr);
            }
        }
        
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

    public void refreshPolicy() {
        try {
            policy = policyBuilder.getPolicy();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    private static String getHostPart(URI uri) {
        StringBuilder sb = new StringBuilder();
        if (uri.getScheme() != null) {
            sb.append(uri.getScheme()).append("://");
        }
        sb.append(uri.getHost());
        if (uri.getPort() != -1) {
            sb.append(":").append(uri.getPort());
        }
        return sb.toString();
    }
    
}
