package com.coverity.security.pie.example.config;

import java.math.BigDecimal;
import java.util.concurrent.Callable;

import com.coverity.security.pie.example.model.Account;
import com.coverity.security.pie.example.service.AccountDao;
import com.coverity.security.pie.example.util.DoPrivileged;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.coverity.security.pie.example.model.Role;
import com.coverity.security.pie.example.model.User;
import com.coverity.security.pie.example.service.UserDao;

public class SampleDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private UserDao userDao;
    
    @Autowired
    private AccountDao accountDao;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        try {
            DoPrivileged.asSystem(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    User user = new User();
                    user.setUsername("Alice");
                    user.setPasswordHash(passwordEncoder.encode("alice"));
                    user.setRole(Role.GUEST);
                    userDao.addUser(user);

                    user = new User();
                    user.setUsername("Bob");
                    user.setPasswordHash(passwordEncoder.encode("bob"));
                    user.setRole(Role.USER);
                    userDao.addUser(user);

                    Account account = new Account();
                    account.setUser(user);
                    account.setBalance(new BigDecimal("234.56"));
                    accountDao.addAccount(account);

                    user = new User();
                    user.setUsername("Carol");
                    user.setPasswordHash(passwordEncoder.encode("carol"));
                    user.setRole(Role.ADMIN);
                    userDao.addUser(user);

                    account = new Account();
                    account.setUser(user);
                    account.setBalance(new BigDecimal("345.67"));
                    accountDao.addAccount(account);

                    return null;
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
    }
}
