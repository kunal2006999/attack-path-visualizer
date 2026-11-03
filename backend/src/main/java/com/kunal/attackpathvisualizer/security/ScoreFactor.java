package com.kunal.attackpathvisualizer.security;

public record ScoreFactor(
        String name,
        int points,
        String reason
) {

    public ScoreFactor {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(
                    "Score factor name cannot be blank"
            );
        }

        if (points < 0) {
            throw new IllegalArgumentException(
                    "Score factor points cannot be negative"
            );
        }

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException(
                    "Score factor reason cannot be blank"
            );
        }
    }
}