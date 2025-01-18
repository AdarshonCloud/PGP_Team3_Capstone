package com.ascendpgp.customerlogin.config.test;

import com.ascendpgp.customerlogin.config.Resilience4jConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = Resilience4jConfig.class)
class Resilience4jConfigTest {

    @Autowired
    private Resilience4jConfig resilience4jConfig;

//    @Test
//    void testCircuitBreakerConfig() {
//        CircuitBreakerConfig config = resilience4jConfig.defaultCircuitBreakerConfig();
//
//        assertNotNull(config, "Circuit breaker config should not be null");
//        assertEquals(50, config.getFailureRateThreshold(), "Failure rate threshold should be 50%");
//        assertEquals(Duration.ofSeconds(10), config.getMaxWaitDurationInHalfOpenState(), "Wait duration should be 10 seconds");
//        assertEquals(5, config.getSlidingWindowSize(), "Sliding window size should be 5");
//    }

    @Test
    void testTimeLimiterConfig() {
        TimeLimiterConfig config = resilience4jConfig.defaultTimeLimiterConfig();

        assertNotNull(config, "Time limiter config should not be null");
        assertEquals(Duration.ofSeconds(2), config.getTimeoutDuration(), "Timeout duration should be 2 seconds");
    }

//    @Test
//    void testRetryConfig() {
//        RetryConfig config = resilience4jConfig.retryConfig();
//
//        assertNotNull(config, "Retry config should not be null");
//        assertEquals(3, config.getMaxAttempts(), "Max attempts should be 3");
//        assertEquals(Duration.ofMillis(500), config.getExceptionPredicate(), "Wait duration should be 500ms");
//    }
}
