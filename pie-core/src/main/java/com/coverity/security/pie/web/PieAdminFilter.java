package com.coverity.security.pie.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import com.coverity.security.pie.core.PolicyEnforcer;

/**
 * A servlet filter which provides an endpoint to retrieve policy violations. At this point its intended use is to
 * facilitate the Maven plugin.
 */
public class PieAdminFilter implements Filter {

    private final PieInitializer pieInitializer;
    
    public PieAdminFilter(PieInitializer pieInitializer) {
        this.pieInitializer = pieInitializer;
    }
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpServletRequest = (HttpServletRequest)request;
            if ("/c0bd580ddcb4666b1PIEec61812f3cdf305".equals(httpServletRequest.getRequestURI())) {
                
                PolicyEnforcer policyEnforcer = pieInitializer.getPolicyEnforcer(httpServletRequest.getParameter("policyEnforcer"));
                String startTimeStr = httpServletRequest.getParameter("startTime");
                Long startTime = (startTimeStr == null ? null : Long.parseLong(startTimeStr));
                
                if (policyEnforcer != null) {
                    PrintWriter writer = response.getWriter();
                    
                    String[][] violations;
                    if (startTime == null) {
                        violations = policyEnforcer.getPolicy().getViolations();
                    } else {
                        violations = policyEnforcer.getPolicy().getViolations(startTime);
                    }
                    
                    for (String[] violation : violations) {
                        if (violation.length > 0) {
                            writer.write(violation[0]);
                        }
                        for (int i = 1; i < violation.length; i++) {
                            writer.write("\t");
                            if (violation[i] != null) {
                                writer.write(violation[i]);
                            }
                        }
                        writer.write("\n");
                    }
                    
                    writer.close();
                    return;
                }
               
            }
        }
        
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }

}
