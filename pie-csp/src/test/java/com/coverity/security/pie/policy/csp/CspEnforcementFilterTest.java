package com.coverity.security.pie.policy.csp;

import com.coverity.security.pie.core.PolicyConfig;
import org.testng.annotations.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import static org.easymock.EasyMock.*;

public class CspEnforcementFilterTest {
    @Test
    public void testPolicyAppliedToRequests() throws IOException, ServletException {
        CspPolicy policy = createMock(CspPolicy.class);
        expect(policy.getPolicyForUri("/foo/bar")).andReturn("response1").anyTimes();
        expect(policy.getPolicyForUri("/fizz/buzz")).andReturn("response2").anyTimes();
        expect(policy.getPolicyForUri(anyObject(String.class))).andReturn("defaultResponse").anyTimes();

        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andReturn(false).anyTimes();

        replay(policy, policyConfig);

        CspEnforcementFilter cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);
        playRequest(cspEnforcementFilter, "/foo/bar", "Content-Security-Policy", "response1; report-uri " + CspEnforcementFilter.REPORT_URI, true);
        playRequest(cspEnforcementFilter, "/fizz/buzz", "Content-Security-Policy", "response2; report-uri " + CspEnforcementFilter.REPORT_URI, true);
        playRequest(cspEnforcementFilter, "/buzz/fizz", "Content-Security-Policy", "defaultResponse; report-uri " + CspEnforcementFilter.REPORT_URI, true);

        verify(policy, policyConfig);
    }

    @Test
    public void testReportOnlyMode() throws IOException, ServletException {
        CspPolicy policy = createMock(CspPolicy.class);
        expect(policy.getPolicyForUri("/foo/bar")).andReturn("response1").anyTimes();
        expect(policy.getPolicyForUri("/fizz/buzz")).andReturn("response2").anyTimes();
        expect(policy.getPolicyForUri(anyObject(String.class))).andReturn("defaultResponse").anyTimes();

        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andReturn(true).anyTimes();

        replay(policy, policyConfig);

        CspEnforcementFilter cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);
        playRequest(cspEnforcementFilter, "/foo/bar", "Content-Security-Policy-Report-Only", "response1; report-uri " + CspEnforcementFilter.REPORT_URI, true);
        playRequest(cspEnforcementFilter, "/fizz/buzz", "Content-Security-Policy-Report-Only", "response2; report-uri " + CspEnforcementFilter.REPORT_URI, true);
        playRequest(cspEnforcementFilter, "/buzz/fizz", "Content-Security-Policy-Report-Only", "defaultResponse; report-uri " + CspEnforcementFilter.REPORT_URI, true);

        verify(policy, policyConfig);
    }

    @Test
    public void testBasicViolationReport() throws IOException, ServletException, URISyntaxException {
        CspPolicy policy = createMock(CspPolicy.class);
        policy.logViolation(new URI("http://foo.bar/a/b/c"), "script-src", "http://fizz.buzz:8080/a/b/c");
        expectLastCall();

        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andReturn(false).anyTimes();

        replay(policy, policyConfig);

        CspEnforcementFilter cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn(CspEnforcementFilter.REPORT_URI);
        expect(request.getInputStream()).andReturn(new DelegateServletInputStream(new ByteArrayInputStream(
                ("{\"csp-report\":{"
                + "\"document-uri\": \"http://foo.bar/a/b/c\","
                + "\"blocked-uri\": \"http://fizz.buzz:8080/a/b/c\","
                + "\"violated-directive\": \"script-src self\""
                + "}}")
                .getBytes(StandardCharsets.UTF_8))));
        HttpServletResponse response = createMock(HttpServletResponse.class);
        FilterChain chain = createStrictMock(FilterChain.class);

        replay(request, response, chain);
        cspEnforcementFilter.doFilter(request, response, chain);
        verify(request, response, chain);

        verify(policy, policyConfig);
    }

    @Test
    public void testSelfViolationReport() throws IOException, ServletException, URISyntaxException {
        CspPolicy policy = createMock(CspPolicy.class);
        policy.logViolation(new URI("http://foo.bar/a/b/c"), "script-src", "'self'");
        expectLastCall();

        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andReturn(false).anyTimes();

        replay(policy, policyConfig);

        CspEnforcementFilter cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn(CspEnforcementFilter.REPORT_URI);
        expect(request.getInputStream()).andReturn(new DelegateServletInputStream(new ByteArrayInputStream(
                ("{\"csp-report\":{"
                        + "\"document-uri\": \"http://foo.bar/a/b/c\","
                        + "\"blocked-uri\": \"http://foo.bar/a/b/c\","
                        + "\"violated-directive\": \"script-src none\""
                        + "}}")
                        .getBytes(StandardCharsets.UTF_8))));
        HttpServletResponse response = createMock(HttpServletResponse.class);
        FilterChain chain = createStrictMock(FilterChain.class);

        replay(request, response, chain);
        cspEnforcementFilter.doFilter(request, response, chain);
        verify(request, response, chain);

        verify(policy, policyConfig);
    }

    @Test
    public void testUnsafeInlineViolationReport() throws IOException, ServletException, URISyntaxException {
        CspPolicy policy = createMock(CspPolicy.class);
        policy.logViolation(new URI("http://foo.bar/a/b/c"), "script-src", "'unsafe-inline'");
        expectLastCall();

        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andReturn(false).anyTimes();

        replay(policy, policyConfig);

        CspEnforcementFilter cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn(CspEnforcementFilter.REPORT_URI);
        expect(request.getInputStream()).andReturn(new DelegateServletInputStream(new ByteArrayInputStream(
                ("{\"csp-report\":{"
                        + "\"document-uri\": \"http://foo.bar/a/b/c\","
                        + "\"blocked-uri\": \"self\","
                        + "\"violated-directive\": \"script-src none\""
                        + "}}")
                        .getBytes(StandardCharsets.UTF_8))));
        HttpServletResponse response = createMock(HttpServletResponse.class);
        FilterChain chain = createStrictMock(FilterChain.class);

        replay(request, response, chain);
        cspEnforcementFilter.doFilter(request, response, chain);
        verify(request, response, chain);

        verify(policy, policyConfig);
    }

    private static void playRequest(CspEnforcementFilter filter,
                                    String uri,
                                    String expectedHeaderName,
                                    String expectedHeaderValue,
                                    boolean filterExpected) throws IOException, ServletException {

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getRequestURI()).andReturn(uri).anyTimes();
        HttpServletResponse response = createMock(HttpServletResponse.class);
        if (expectedHeaderName != null) {
            response.addHeader(expectedHeaderName, expectedHeaderValue);
            expectLastCall();
        }
        FilterChain chain = createStrictMock(FilterChain.class);
        if (filterExpected) {
            chain.doFilter(request, response);
            expectLastCall();
        }

        replay(request, response, chain);
        filter.doFilter(request, response, chain);
        verify(request, response, chain);
    }

    private static class DelegateServletInputStream extends ServletInputStream {

        private final InputStream delegate;
        public DelegateServletInputStream(InputStream is) {
            delegate = is;
        }

        @Override
        public int read() throws IOException {
            return delegate.read();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

}
