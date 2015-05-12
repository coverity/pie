package com.coverity.security.pie.web;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.test.TestPolicyEnforcer;
import org.testng.annotations.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.easymock.EasyMock.*;
import static org.testng.Assert.assertEquals;

public class PieAdminFilterTest {
    @Test
    public void testPieAdminFilter() throws IOException, ServletException, InterruptedException {

        TestPolicyEnforcer testPolicyEnforcer = new TestPolicyEnforcer();
        testPolicyEnforcer.init(new PieConfig());

        testPolicyEnforcer.getPolicy().doLogViolation("foo", "bar");
        final long startTime = System.currentTimeMillis()+1;
        Thread.sleep(10L);
        testPolicyEnforcer.getPolicy().doLogViolation("fizz", "buzz");

        PieInitializer pieInitializer = createMock(PieInitializer.class);
        expect(pieInitializer.getPolicyEnforcer("simple")).andReturn(testPolicyEnforcer).anyTimes();
        replay(pieInitializer);

        PieAdminFilter pieAdminFilter = new PieAdminFilter(pieInitializer);

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn("/my-app/foo/bar").anyTimes();
        expect(request.getContextPath()).andReturn("/my-app").anyTimes();

        HttpServletResponse response = createMock(HttpServletResponse.class);
        FilterChain chain = createMock(FilterChain.class);
        chain.doFilter(request, response);
        expectLastCall();

        replay(request, response, chain);
        pieAdminFilter.doFilter(request, response, chain);
        // Verify that nothing happened with the response and that chain filter is called
        verify(request, response, chain);


        // Now test a call to the filter
        request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn("/my-app" + PieAdminFilter.ADMIN_FILTER_URI).anyTimes();
        expect(request.getContextPath()).andReturn("/my-app").anyTimes();
        expect(request.getParameter("policyEnforcer")).andReturn("simple").anyTimes();
        expect(request.getParameter("startTime")).andReturn(null).anyTimes();

        StringWriter output = new StringWriter();
        response = createMock(HttpServletResponse.class);
        expect(response.getWriter()).andReturn(new PrintWriter(output)).anyTimes();
        chain = createMock(FilterChain.class);

        replay(request, response, chain);
        pieAdminFilter.doFilter(request, response, chain);
        // Verify that chain filter is NOT called
        verify(request, response, chain);
        // Verify output
        assertEquals(output.toString(), "=== PIE REPORT ===\nfoo\tbar\nfizz\tbuzz\n");


        // Now test with a startTime parameter
        request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn("/my-app" + PieAdminFilter.ADMIN_FILTER_URI).anyTimes();
        expect(request.getContextPath()).andReturn("/my-app").anyTimes();
        expect(request.getParameter("policyEnforcer")).andReturn("simple").anyTimes();
        expect(request.getParameter("startTime")).andReturn(Long.toString(startTime)).anyTimes();

        output = new StringWriter();
        response = createMock(HttpServletResponse.class);
        expect(response.getWriter()).andReturn(new PrintWriter(output)).anyTimes();
        chain = createMock(FilterChain.class);

        replay(request, response, chain);
        pieAdminFilter.doFilter(request, response, chain);
        // Verify that chain filter is NOT called
        verify(request, response, chain);
        // Verify output
        assertEquals(output.toString(), "=== PIE REPORT ===\nfizz\tbuzz\n");

        verify(pieInitializer);
    }
}
