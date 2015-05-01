package com.coverity.security.pie.example.util;

import java.util.Arrays;
import java.util.concurrent.Callable;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.coverity.security.pie.example.model.Role;

public class DoPrivileged {
    public static <T> T asSystem(Callable<T> callable) throws Exception {
        final SecurityContext priorContext = SecurityContextHolder.getContext();
        try {
            SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
            PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
                    "system", null, Arrays.asList(new SimpleGrantedAuthority(Role.SYSTEM.toString())));
            SecurityContextHolder.getContext().setAuthentication(token);
            
            return callable.call();
        } finally {
            SecurityContextHolder.setContext(priorContext);
        }
        
    }
}
