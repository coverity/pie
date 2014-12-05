package com.coverity.pie.util;

import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;

public class IOUtil {
    public static void closeSilently(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                // Do nothing
            }
        }
    }
    
    public static String readFile(File file) throws IOException {
        return toString(new FileReader(file));
    }
    public static String readFile(String file) throws IOException {
        return toString(new FileReader(file));
    }
    public static String readFile(URL file) throws IOException {
        return toString(file.openStream());
    }
    
    public static String toString(InputStream is) throws IOException {
        try {
            return toString(new InputStreamReader(is));
        } finally {
            closeSilently(is);
        }
    }
    public static String toString(Reader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        try {
            char buffer[] = new char[4096];
            int n;
            while ((n = reader.read(buffer)) > 0) {
                sb.append(buffer, 0, n);
            }
            reader.close();
        } catch (IOException e) {
            closeSilently(reader);
            throw e;
        }
        return sb.toString();
    }
    
    
    public static void writeFile(File file, String content) throws IOException {
        writeFile(new FileWriter(file), content);
    }
    private static void writeFile(FileWriter fw, String content) throws IOException {
        try {
            fw.write(content);
            fw.close();
        } catch (IOException e) {
            closeSilently(fw);
            throw e;
        }
    }
    
}
