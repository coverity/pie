package com.coverity.pie.example.config;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;

import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

import com.coverity.pie.plugin.springsecurity.PieMethodSecurityConfig;

public class WebAppInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
        applicationContext.register(AppConfig.class, SecurityConfig.class, PieMethodSecurityConfig.class);
        servletContext.addListener(new ContextLoaderListener(applicationContext));
        
        ServletRegistration.Dynamic dispatcher = servletContext.addServlet("dispatcherServlet", new DispatcherServlet(applicationContext));
        dispatcher.setLoadOnStartup(1);
        dispatcher.addMapping("/");
    }

}
