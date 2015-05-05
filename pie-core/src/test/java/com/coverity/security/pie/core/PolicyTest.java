package com.coverity.security.pie.core;

import static org.testng.Assert.assertEquals;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.coverity.security.pie.util.IOUtil;

public class PolicyTest {
    
    @Test
    public void testEmptyPolicy() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        Policy policy = new SimplePolicy();
        policy.writePolicy(new FileWriter(file));
        assertEquals(IOUtil.readFile(file), "{\n}\n");
    }
    
    @Test
    public void testParseFile() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        final String contents = "{\n"
                + "    \"firstFact\": {\n"
                + "        \"secondFact\": {},\n"
                + "        \"thirdFact\": {}\n"
                + "    },\n"
                + "    \"fourthFact\": {\n"
                + "        \"fifthFact\": {\n"
                + "            \"sixthFact\": {}\n"
                + "        }\n"
                + "    }\n"
                + "}\n";
        
        IOUtil.writeFile(file, contents);
        Policy policy = new SimplePolicy();
        policy.parsePolicy(new FileReader(file));
        
        Assert.assertTrue(policy.implies("firstFact", "secondFact"));
        Assert.assertTrue(policy.implies("firstFact", "thirdFact"));
        Assert.assertTrue(policy.implies("fourthFact", "fifthFact", "sixthFact"));
        Assert.assertFalse(policy.implies("whatFact", "secondFact"));
        Assert.assertFalse(policy.implies("firstFact", "whatFact"));
        Assert.assertFalse(policy.implies("fourthFact", "fakeFact", "sixthFact"));
        Assert.assertFalse(policy.implies("fourthFact", "fakeFact", "sixthFact", "extraFact"));
    }

    @Test
    public void testQuotedFact() throws IOException {
        Policy policy = new SimplePolicy();
        policy.logViolation("foo \\a \"bar\" \\b baz");
        policy.addViolationsToPolicy();
        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        sw.close();
        Assert.assertEquals(sw.toString(),
                "{\n"
                + "   \"foo \\\\a \\\"bar\\\" \\\\b baz\": {}\n"
                + "}\n"
                );
    }

    @Test
    public void testConcurrency() throws ExecutionException, InterruptedException {
        final Policy policy = new SimplePolicy();
        policy.logViolation("foo", "bar", "baz");
        policy.logViolation("foo", "oof", "ofo");
        policy.addViolationsToPolicy();

        final Callable<Boolean> reader = new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
                try {
                    for (int i = 0; i < 1000; i++) {
                        policy.implies("foo", "bar", "baz");
                        policy.implies("foo", "oof", "ofo");
                        policy.implies("1", "2", "3");
                    }
                } catch (Exception e) {
                    System.err.println(e);
                    return false;
                }
                return true;
            }
        };

        final Callable<Boolean> writer = new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
                try {
                    for (int i = 0; i < 1000; i++) {
                        policy.logViolation(Integer.toString(i % 10), Integer.toString((i / 10) % 10), Integer.toString((i / 100) % 10));
                        policy.addViolationsToPolicy();
                    }
                } catch (Exception e) {
                    System.err.println(e);
                    return false;
                }
                return true;
            }
        };

        ExecutorService exec = Executors.newFixedThreadPool(4);
        final List<Future<Boolean>> errors = new ArrayList<Future<Boolean>>();
        errors.add(exec.submit(reader));
        errors.add(exec.submit(writer));
        errors.add(exec.submit(reader));
        errors.add(exec.submit(writer));
        exec.shutdown();
        for (Future<Boolean> errorMsg : errors)
        {
            Assert.assertTrue(errorMsg.get());
        }
    }
}
