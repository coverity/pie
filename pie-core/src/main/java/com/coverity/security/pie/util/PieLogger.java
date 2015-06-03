package com.coverity.security.pie.util;

import com.coverity.security.pie.core.PieConfig;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class PieLogger {
    private static PieConfig pieConfig = null;
    private static PrintWriter logWriter = null;

    public static void setPieConfig(PieConfig pieConfig) {
        PieLogger.pieConfig = pieConfig;
        if (logWriter != null) {
            IOUtil.closeSilently(logWriter);
            logWriter = null;
        }
        if (pieConfig != null && pieConfig.isLoggingEnabled()) {
            try {
                logWriter = new PrintWriter(new OutputStreamWriter(new FileOutputStream(pieConfig.getLogPath(), true), StandardCharsets.UTF_8));
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static enum LogLevel {
        DEBUG,
        INFO,
        WARN,
        ERROR
    }

    public static void log(LogLevel logLevel, String msg, Throwable throwable) {
        if (logWriter == null) {
            return;
        }
        logWriter.append("[").append(new Date().toString()).append("] ").append(logLevel.toString()).append(": ").append(msg).append("\n");
        if (throwable != null) {
            throwable.printStackTrace(logWriter);
        }
        logWriter.flush();
    }

    public static void log(LogLevel logLevel, String msg) {
        log(logLevel, msg, null);
    }

    public static void debug(String msg) {
        log(LogLevel.DEBUG, msg);
    }
    public static void debug(String msg, Throwable throwable) {
        log(LogLevel.DEBUG, msg, throwable);
    }
    public static void info(String msg) {
        log(LogLevel.INFO, msg);
    }
    public static void info(String msg, Throwable throwable) {
        log(LogLevel.INFO, msg, throwable);
    }
    public static void warn(String msg) {
        log(LogLevel.WARN, msg);
    }
    public static void warn(String msg, Throwable throwable) {
        log(LogLevel.WARN, msg, throwable);
    }
    public static void error(String msg) {
        log(LogLevel.ERROR, msg);
    }
    public static void error(String msg, Throwable throwable) {
        log(LogLevel.ERROR, msg, throwable);
    }

}
