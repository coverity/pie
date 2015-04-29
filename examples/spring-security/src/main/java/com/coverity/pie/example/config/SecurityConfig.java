package com.coverity.pie.example.config;

import java.util.Arrays;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.coverity.pie.example.model.User;

@Configuration
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @PersistenceContext
    private EntityManager entityManager;
    
    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth, final PasswordEncoder passwordEncoder) throws Exception {
        auth.authenticationProvider(new AuthenticationProvider() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                List<?> result = entityManager.createQuery("SELECT U FROM User U WHERE U.username = :username")
                        .setParameter("username", authentication.getName())
                        .getResultList();
                if (result.size() == 0) {
                    throw new UsernameNotFoundException("Invalid username.");
                }
                User user = (User)result.get(0);
                if (!passwordEncoder.matches((CharSequence)authentication.getCredentials(), user.getPasswordHash())) {
                    throw new BadCredentialsException("Invalid password.");
                }
                return new UsernamePasswordAuthenticationToken(user.getUsername(),
                        user.getPasswordHash(), Arrays.asList(new SimpleGrantedAuthority(user.getRole().toString())));
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return true;
            }
            
        });
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
