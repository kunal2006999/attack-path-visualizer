package com.kunal.attackpathvisualizer.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RiskScorerTest {

    private RiskScorer scorer;

    @BeforeEach
    void setUp() {
        scorer = new RiskScorer();
    }

    @Test
    void shouldSumRiskFactors() {
        List<ScoreFactor> factors = List.of(
                new ScoreFactor("SENSITIVITY", 30, "Sensitive target"),
                new ScoreFactor("PERMISSIONS", 25, "Broad permissions"),
                new ScoreFactor("PATH_LENGTH", 5, "Short path")
        );

        assertEquals(60, scorer.calculateScore(factors));
    }

    @Test
    void shouldCapScoreAtOneHundred() {
        List<ScoreFactor> factors = List.of(
                new ScoreFactor("FACTOR_A", 70, "First factor"),
                new ScoreFactor("FACTOR_B", 60, "Second factor")
        );

        assertEquals(100, scorer.calculateScore(factors));
    }

    @Test
    void shouldReturnZeroForEmptyFactors() {
        assertEquals(0, scorer.calculateScore(List.of()));
    }

    @Test
    void shouldReturnLowSeverityAtZero() {
        assertEquals(Severity.LOW, scorer.calculateSeverity(0));
    }

    @Test
    void shouldReturnLowSeverityImmediatelyBelowMediumBoundary() {
        assertEquals(Severity.LOW, scorer.calculateSeverity(34));
    }

    @Test
    void shouldReturnMediumSeverityAtBoundary() {
        assertEquals(Severity.MEDIUM, scorer.calculateSeverity(35));
    }

    @Test
    void shouldReturnMediumSeverityImmediatelyBelowHighBoundary() {
        assertEquals(Severity.MEDIUM, scorer.calculateSeverity(54));
    }

    @Test
    void shouldReturnHighSeverityAtBoundary() {
        assertEquals(Severity.HIGH, scorer.calculateSeverity(55));
    }

    @Test
    void shouldReturnHighSeverityImmediatelyBelowCriticalBoundary() {
        assertEquals(Severity.HIGH, scorer.calculateSeverity(74));
    }

    @Test
    void shouldReturnCriticalSeverityAtBoundary() {
        assertEquals(Severity.CRITICAL, scorer.calculateSeverity(75));
    }

    @Test
    void shouldReturnCriticalSeverityAtMaximumScore() {
        assertEquals(Severity.CRITICAL, scorer.calculateSeverity(100));
    }

    @Test
    void shouldRejectNegativeRiskScore() {
        assertThrows(
                IllegalArgumentException.class,
                () -> scorer.calculateSeverity(-1)
        );
    }

    @Test
    void shouldRejectScoreAboveOneHundred() {
        assertThrows(
                IllegalArgumentException.class,
                () -> scorer.calculateSeverity(101)
        );
    }

    @Test
    void shouldRejectNullFactors() {
        assertThrows(
                NullPointerException.class,
                () -> scorer.calculateScore(null)
        );
    }

    @Test
    void shouldRejectNullFactorInsideList() {
        assertThrows(
                NullPointerException.class,
                () -> scorer.calculateScore(
                        java.util.Arrays.asList(
                                new ScoreFactor(
                                        "SENSITIVITY",
                                        30,
                                        "Sensitive target"
                                ),
                                null
                        )
                )
        );
    }
}