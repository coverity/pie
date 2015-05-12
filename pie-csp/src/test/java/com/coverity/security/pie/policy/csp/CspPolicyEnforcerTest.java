package com.coverity.security.pie.policy.csp;

import com.coverity.security.pie.core.PieConfig;
import org.testng.annotations.Test;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import static org.easymock.EasyMock.*;

public class CspPolicyEnforcerTest {
    @Test
    public void testApplyPolicy() {
        CspPolicyEnforcer cspPolicyEnforcer = new CspPolicyEnforcer();
        cspPolicyEnforcer.init(new PieConfig());

        FilterRegistration.Dynamic filterRegistration = createStrictMock(FilterRegistration.Dynamic.class);
        ServletContext servletContext = createStrictMock(ServletContext.class);
        // Make sure a CspEnforcementFilter is getting added to the ServletContext
        expect(servletContext.addFilter(anyObject(String.class), anyObject(CspEnforcementFilter.class)))
                .andReturn(filterRegistration);
        // This is the important part of the test: make sure the filter is matching all urls and is applied
        // before other filters
        filterRegistration.addMappingForUrlPatterns(null, false, "/*");
        expectLastCall();
        replay(servletContext, filterRegistration);

        cspPolicyEnforcer.applyPolicy(servletContext);

        verify(servletContext, filterRegistration);
    }
}
