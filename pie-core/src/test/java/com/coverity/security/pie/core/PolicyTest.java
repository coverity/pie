package com.coverity.security.pie.core;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

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
}
