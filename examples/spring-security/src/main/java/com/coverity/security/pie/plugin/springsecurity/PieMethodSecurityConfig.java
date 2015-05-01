package com.coverity.security.pie.plugin.springsecurity;

import javax.servlet.ServletContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, proxyTargetClass = true)
public class PieMethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    
    @Autowired
    private ServletContext servletContext;
    
    @Override
    protected AccessDecisionManager accessDecisionManager() {
        final SpringSecurityPolicyEnforcer policyEnforcer = (SpringSecurityPolicyEnforcer)servletContext.getAttribute(SpringSecurityPolicyEnforcer.SPRING_SECURITY_POLICY_ATTRIBUTE);
        if (policyEnforcer == null) {
            throw new IllegalStateException("Spring policy enforcer wasn't initialized.");
        }
        
        return new PieAccessDecisionManager(policyEnforcer);
    }
}
