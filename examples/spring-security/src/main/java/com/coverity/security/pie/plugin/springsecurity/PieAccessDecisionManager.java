package com.coverity.security.pie.plugin.springsecurity;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

import com.coverity.security.pie.example.model.Role;

public class PieAccessDecisionManager implements AccessDecisionManager {

    private final SpringSecurityPolicyEnforcer policyEnforcer;
    
    public PieAccessDecisionManager(SpringSecurityPolicyEnforcer policyEnforcer) {
        this.policyEnforcer = policyEnforcer;
    }
    
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {
        
        if (!(object instanceof MethodInvocation)) {
            throw new IllegalStateException("Only operates on methods.");
        }
        MethodInvocation methodInvocation = (MethodInvocation)object;
        
        Role role = null;
        if (authentication != null && authentication.getAuthorities().size() > 0) {
            role = Role.valueOf(authentication.getAuthorities().iterator().next().getAuthority());
        }
        if (role == null) {
            throw new AccessDeniedException("Secured method must have an authenticated role.");
        }
        
        if (!policyEnforcer.getPolicy().implies(role, methodInvocation.getThis().getClass(), methodInvocation.getMethod())) {
            policyEnforcer.getPolicy().logViolation(role, methodInvocation.getThis().getClass(), methodInvocation.getMethod());
            if (!policyEnforcer.getPolicyConfig().isReportOnlyMode()) {
                throw new AccessDeniedException("Access Denied");
            }
        }
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz == MethodInvocation.class;
    }

}
