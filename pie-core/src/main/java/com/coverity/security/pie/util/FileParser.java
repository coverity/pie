package com.coverity.security.pie.util;

import java.util.ArrayList;
import java.util.List;

/**
 * A generic set of methods for parsing files; used in particular for parsing native Java SecurityManager policies.
 */
public class FileParser {
    public static String[] tokenize(String input, char[] specialChars) {
        List<String> tokens = new ArrayList<String>();
        
        StringBuilder sb = new StringBuilder();
        boolean inQuote = false;
        for (int pos = 0; pos < input.length(); pos++) {
            char c = input.charAt(pos);
            if (c == '"') {
                inQuote = !inQuote;
            }
            
            if (!inQuote && (c == ' ' || c == '\n')) {
                if (sb.length() > 0) {
                    tokens.add(sb.toString());
                    sb.setLength(0);
                }
            } else if (!inQuote && inArray(c, specialChars)) {
                if (sb.length() > 0) {
                    tokens.add(sb.toString());
                    sb.setLength(0);
                }
                tokens.add(Character.toString(c));
            } else {
                sb.append(c);
            }
        }
        if (sb.length() > 0) {
            tokens.add(sb.toString());
        }
        
        return tokens.toArray(new String[tokens.size()]);
    }
    
    private static boolean inArray(char c, char[] arr) {
        for (int i = 0; i < arr.length; i++) {
            if (c == arr[i]) {
                return true;
            }
        }
        return false;
    }
    
    public static int nextToken(String token, String tokens[], int off) {
        int i = off;
        while (i < tokens.length) {
            if (tokens[i].equals(token)) {
                break;
            }
            i++;
        }
        if (i >= tokens.length) {
            return -1;
        }
        return i;
    }
}
