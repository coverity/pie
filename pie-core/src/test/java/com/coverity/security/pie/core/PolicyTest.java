package com.coverity.security.pie.core;

import static org.testng.Assert.assertEquals;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.coverity.security.pie.util.IOUtil;

public class PolicyTest {
    
    @Test
    public void testEmptyPolicy() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        Policy policy = new SimplePolicy();
        policy.writePolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
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
        policy.parsePolicy(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));

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

    @Test
    public void testGetGrants() {
        Policy policy = new SimplePolicy();
        policy.logViolation("a", "b", "c");
        policy.logViolation("b", "c", "d");
        policy.logViolation("b", "d", "c");
        policy.logViolation("c", "b", "f");
        policy.addViolationsToPolicy();

        assertArrayCollectionEquals(policy.getGrants(null, null, "c"), Arrays.asList(
                new String[]{"a", "b", "c"},
                new String[]{"b", "d", "c"}));

        assertArrayCollectionEquals(policy.getGrants(null, "b", "c"), Arrays.<String[]>asList(
                new String[]{"a", "b", "c" }));

        assertArrayCollectionEquals(policy.getGrants("c", null, null), Arrays.<String[]>asList(
                new String[]{"c", "b", "f"}));

        assertArrayCollectionEquals(policy.getGrants(null, null, "c", null, null), Arrays.asList(
                new String[]{"a", "b", "c", null, null},
                new String[]{"b", "d", "c", null, null}));

        assertArrayCollectionEquals(policy.getGrants(null, null, "c", "f", null), Arrays.<String[]>asList());
        assertArrayCollectionEquals(policy.getGrants(null, null, "c", null, "f"), Arrays.<String[]>asList());
    }

    private static class ArrayComparator<T extends Comparable> implements Comparator<T[]> {
        @Override
        public int compare(T[] o1, T[] o2) {
            if (o1.length != o2.length) {
                return o1.length - o2.length;
            }
            for (int i = 0; i < o1.length; i++) {
                T a = o1[i];
                T b = o2[i];
                if (a == null && b == null) { continue; }
                if (a == null && b != null) { return -1; }
                if (a != null && b == null) { return 1; }

                int c = a.compareTo(b);
                if (c != 0) { return c; }
            }
            return 0;
        }
    }

    private static <T extends Comparable> void assertArrayCollectionEquals(Collection<T[]> a, Collection<T[]> b) {
        assertEquals(a.size(), b.size());

        List<T[]> aList = new ArrayList<T[]>(a);
        List<T[]> bList = new ArrayList<T[]>(b);
        final ArrayComparator<T> arrayComparator = new ArrayComparator<T>();
        Collections.sort(aList, arrayComparator);
        Collections.sort(bList, arrayComparator);

        for (int i = 0; i < aList.size(); i++) {
            if (arrayComparator.compare(aList.get(i), bList.get(i)) != 0) {
                throw new AssertionError("Different values:\n" + Arrays.toString(aList.get(i)) + "\n" + Arrays.toString(bList.get(i)));
            }
        }
    }
}
