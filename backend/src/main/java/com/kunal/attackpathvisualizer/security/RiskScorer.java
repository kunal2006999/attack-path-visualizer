package com.kunal.attackpathvisualizer.security;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

@Component
public class RiskScorer {

    private static final int MAX_RISK_SCORE = 100;

    public int calculateScore(List<ScoreFactor> factors) {
        Objects.requireNonNull(
                factors,
                "Score factors cannot be null"
        );

        int total = 0;

        for (ScoreFactor factor : factors) {
            Objects.requireNonNull(
                    factor,
                    "Score factor cannot be null"
            );

            total = Math.addExact(total, factor.points());

            if (total >= MAX_RISK_SCORE) {
                return MAX_RISK_SCORE;
            }
        }

        return total;
    }

    public Severity calculateSeverity(int riskScore) {
        return Severity.of(riskScore);
    }
}