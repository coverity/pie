package com.coverity.security.pie.util;

import java.util.List;

public class StringUtil {
    public static String join(String s, String[] arr, int off, int end) {
        if (off < 0 || end > arr.length) {
            throw new IllegalArgumentException("Invalid indices");
        }
        if (end <= off) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < end-1; i++) {
            sb.append(arr[i]).append(s);
        }
        sb.append(arr[end-1]);
        return sb.toString();
    }
    
    public static String join(String s, List<String> strings) {
        if (strings.size() == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < strings.size()-1; i++) {
            sb.append(strings.get(i)).append(s);
        }
        sb.append(strings.get(strings.size()-1));
        return sb.toString();
    }
    

    public static String join(String s, String ... strings) {
        if (strings.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < strings.length-1; i++) {
            sb.append(strings[i]).append(s);
        }
        sb.append(strings[strings.length-1]);
        return sb.toString();
    }
}
