// (c) 2014 Coverity, Inc. All rights reserved worldwide.
package com.coverity.pie.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

import com.coverity.pie.example.model.Role;
import com.coverity.pie.example.service.AccountDao;
import com.coverity.pie.example.service.UserDao;

@Controller
public class HelloWorldController {
    
    @Autowired
    private UserDao userDao;
    
    @Autowired
    private AccountDao accountDao;
    
    @RequestMapping("getUsers")
    public ModelMap getUsers() {
        
        if (!SecurityContextHolder.getContext().getAuthentication().getAuthorities()
                .contains(new SimpleGrantedAuthority(Role.ADMIN.toString()))) {
            throw new IllegalArgumentException("User cannot access this endpoint.");
        }
        
        return new ModelMap()
            .addAttribute("users", userDao.getUsers());
    }
    
    @RequestMapping("getAccount")
    public ModelMap getAccount() {
        
        if (!SecurityContextHolder.getContext().getAuthentication().getAuthorities()
                .contains(new SimpleGrantedAuthority(Role.USER.toString()))) {
            throw new IllegalArgumentException("User cannot access this endpoint.");
        }
        final String username = SecurityContextHolder.getContext().getAuthentication().getName();
        
        return new ModelMap()
            .addAttribute("account", accountDao.getAccount(username));
    }
}
