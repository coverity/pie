package com.coverity.pie.policy.csp;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.coverity.pie.util.FileParser;
import com.coverity.pie.util.IOUtil;

public class CspPolicyFileUtil {
    public static CspPolicy parseFile(URL file) throws IOException {
        CspPolicy policy = new CspPolicy();
        
        InputStream fileInputStream = null;
        try {
            fileInputStream = file.openStream();
        } catch (IOException e) {
            IOUtil.closeSilently(fileInputStream);
            return policy;
        }
        
        String[] tokens = FileParser.tokenize(IOUtil.toString(fileInputStream), new char[]{ ';', '{', '}' });
        
        List<CspPolicyEntry> policyEntries = policy.getPolicyEntries();
        
        int pos = 0;
        while (pos < tokens.length) {
            if (tokens.length <= pos+1 || !tokens[pos+1].equals("{")) {
                throw new IllegalArgumentException("Invalid file format.");
            }
            
            String uri = tokens[pos];
            Map<String, List<String>> directives = new HashMap<String, List<String>>();
            
            pos += 2;
            int next = FileParser.nextToken(";", tokens, pos);
            if (next == -1) {
                throw new IllegalArgumentException("Invalid file format.");
            }
            while (!tokens[pos].equals("}")) {
                
                String directive = tokens[pos];
                List<String> values = new ArrayList<String>(next-pos-1);
                for (int i = pos+1; i < next; i++) {
                    values.add(tokens[i]);
                }
                directives.put(directive, values);
                
                pos = next+1;
                next = FileParser.nextToken(";", tokens, pos);
                if (next == -1) {
                    throw new IllegalArgumentException("Invalid file format.");
                }
            }
            
            policyEntries.add(new CspPolicyEntry(uri, directives));
            pos = next+1;
        }
        
        return policy;
    }
    
    public static void writeFile(URL path, CspPolicy policy) throws IOException {
        if (!path.getProtocol().equals("file")) {
            throw new IllegalArgumentException("path must be a file");
        }
        
        FileWriter fw = null;
        try {
            fw = new FileWriter(path.getPath());
            
            List<CspPolicyEntry> entries = policy.getPolicyEntries();
            Collections.sort(entries, new Comparator<CspPolicyEntry>() {
                @Override
                public int compare(CspPolicyEntry a, CspPolicyEntry b) {
                    return a.getUri().compareTo(b.getUri());
                }
            });
            
            for (CspPolicyEntry entry : entries) {
                fw.write(entry.getUri());
                fw.write(" {\n");
                
                List<Map.Entry<String, List<String>>> directives = new ArrayList<>(entry.getDirectives().entrySet());
                Collections.sort(directives, new Comparator<Map.Entry<String, List<String>>>() {
                    @Override
                    public int compare(Map.Entry<String, List<String>> a, Map.Entry<String, List<String>> b) {
                        return a.getKey().compareTo(b.getKey());
                    }
                });
                
                for (Map.Entry<String, List<String>> directive : directives) {
                    List<String> values = directive.getValue();
                    Collections.sort(values);
                    
                    fw.write("    ");
                    fw.write(directive.getKey());
                    for (String value : values) {
                        fw.write(' ');
                        fw.write(value);
                    }
                    fw.write(";\n");
                }
                fw.write("};\n");
            }
        }
        finally {
            IOUtil.closeSilently(fw);
        }
    }
}
