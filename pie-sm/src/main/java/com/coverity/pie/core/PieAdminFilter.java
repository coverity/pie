package com.coverity.pie.core;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

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
                if (policyEnforcer != null) {
                    PrintWriter writer = response.getWriter();
                    writer.write(policyEnforcer.getPolicyViolations());
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
