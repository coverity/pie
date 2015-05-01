package com.coverity.security.pie.plugin.springsecurity;

import java.lang.reflect.Method;

import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.Policy;
import com.coverity.security.pie.example.model.Role;
import com.coverity.security.pie.plugin.springsecurity.fact.RoleFactMetaData;

public class SpringSecurityPolicy extends Policy {

    @Override
    public String getName() {
        return "springSecurity";
    }

    @Override
    public FactMetaData getRootFactMetaData() {
        return RoleFactMetaData.getInstance();
    }
    
    public boolean implies(Role role, Class<?> beanClass, Method method) {
        return super.implies(role.toString(), beanClass.getName(), method.getName());
    }
    public void logViolation(Role role, Class<?> beanClass, Method method) {
        super.logViolation(role.toString(), beanClass.getName(), method.getName());    
    }

}
