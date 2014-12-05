package com.coverity.pie.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.coverity.pie.policy.securitymanager.PermissionRequest;
import com.coverity.pie.util.IOUtil;
import com.coverity.pie.util.StringUtil;

import fi.iki.elonen.NanoHTTPD;

public class TestPieServer extends NanoHTTPD {
    
    private final Semaphore shutdownSemaphore = new Semaphore(0);

    public static void main(String[] args) throws IOException {
        if (args.length > 0 && args[0].equals("shutdown")) {
            CloseableHttpClient httpclient = HttpClients.createDefault();
            
            HttpGet httpGet = new HttpGet("http://localhost:18885/shutdown");
            CloseableHttpResponse response1 = null;
            response1 = httpclient.execute(httpGet);
            response1.close();
            httpclient.close();
            
            return;
        }
        
        TestPieServer server = new TestPieServer();
        
        server.start();
        server.shutdownSemaphore.acquireUninterruptibly();
        server.stopGracefully();
    }
    
    public TestPieServer() {
        super(18885);
    }
    
    private final Set<String> clearedViolations = new HashSet<String>();

    @Override
    public Response serve(IHTTPSession session) {
        final String[] uriParts = session.getUri().substring(1).split("/");
        
        if (uriParts.length == 1 && uriParts[0].equals("shutdown")) {
            shutdownSemaphore.release();
            return new Response(Response.Status.OK, MIME_PLAINTEXT, "OK");
        }
        
        if (!uriParts[uriParts.length-1].equals("c0bd580ddcb4666b1PIEec61812f3cdf305")) {
            return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not found.");
        }
        
        final String testFile = StringUtil.join("_", uriParts, 0, uriParts.length-1);
        final InputStream testFileResource = this.getClass().getResourceAsStream("/" + testFile);
        if (testFileResource == null) {
            return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not found.");
        }
        
        Collection<PermissionRequest> permissionRequests;
        if (clearedViolations.contains(testFile.toString())) {
            permissionRequests = Collections.emptyList();
        } else {
            try {
                permissionRequests = readPermissionRequests(testFileResource);
            } catch (IOException e) {
                return new Response(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, e.toString());
            }
        }
        
        Map<String, List<String>> decodedQueryParameters = decodeParameters(session.getQueryParameterString());
        if (!decodedQueryParameters.containsKey("policyEnforcer") || !decodedQueryParameters.get("policyEnforcer").get(0).equals("SecurityManager")) {
            return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not found.");
        }
        
        if (decodedQueryParameters.containsKey("clearViolations")) {
            if (decodedQueryParameters.get("clearViolations").get(0).equals("true")) {
                clearedViolations.add(testFile.toString());
            }
        }
        
        Long startTime = null;
        if (decodedQueryParameters.containsKey("startTime")) {
            startTime = Long.parseLong(decodedQueryParameters.get("startTime").get(0));
        }
        
        StringBuilder response = new StringBuilder();
        for (PermissionRequest permissionRequest : permissionRequests) {
            if (startTime != null && startTime > permissionRequest.getRequestTime()) {
                continue;
            }
            response.append(permissionRequest.getRequestTime()).append("\t")
                    .append(permissionRequest.getCodeSource()).append("\t")
                    .append(permissionRequest.getClassName()).append("\t")
                    .append(permissionRequest.getPermissionClassName()).append("\t")
                    .append(permissionRequest.getPermissionName()).append("\t")
                    .append(permissionRequest.getPermissionAction()).append("\t")
                    .append("\n");
        }
        
        return new Response(Response.Status.OK, MIME_PLAINTEXT, response.toString());
    }
    
    private static Collection<PermissionRequest> readPermissionRequests(InputStream is) throws IOException {
        InputStreamReader isr = null;
        BufferedReader br = null;
        
        Collection<PermissionRequest> permissionRequests = new ArrayList<PermissionRequest>();
        try {
            isr = new InputStreamReader(is);
            br = new BufferedReader(isr);
            String line;
            
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\t");
                permissionRequests.add(new PermissionRequest(
                        Long.parseLong(parts[0]), parts[1], parts[2], parts[3], parts[4], parts[5]
                        ));
            }
        } finally {
            IOUtil.closeSilently(br);
            IOUtil.closeSilently(isr);
            IOUtil.closeSilently(is);
        }
        return permissionRequests;
    }
}
