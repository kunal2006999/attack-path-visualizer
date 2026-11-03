package com.kunal.attackpathvisualizer.security;

public enum Severity {

    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public static Severity of(int score) {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException(
                    "Risk score must be between 0 and 100"
            );
        }

        if (score >= 75) {
            return CRITICAL;
        }

        if (score >= 55) {
            return HIGH;
        }

        if (score >= 35) {
            return MEDIUM;
        }

        return LOW;
    }
}