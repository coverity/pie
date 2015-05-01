package com.coverity.security.pie.policy.csp;

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

import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.util.IOUtil;

/**
 * A servlet filter which adds the CSP directive to the response and which handles violation reports send by the agent.
 */
public class CspEnforcementFilter implements Filter {

    private static final String REPORT_URI = "/a379568856ef23aPIE19bc95ce4e2f7fd2b";
    
    private final CspPolicy policy;
    private final PolicyConfig policyConfig;
    
    public CspEnforcementFilter(CspPolicy policy, PolicyConfig policyConfig) {
        this.policy = policy;
        this.policyConfig = policyConfig;
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
                
                policy.logViolation(documentUri, violatedDirectiveName, blocked);
            } catch (JSONException | URISyntaxException e) {
                throw new IllegalArgumentException("Invalid request", e);
            }
            return;
        }
        
        if (policy != null) {
            
            String policyStr = policy.getPolicyForUri(httpServletRequest.getRequestURI());
            policyStr += "; report-uri " + REPORT_URI;
            
            if (policyConfig.isReportOnlyMode()) {
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
