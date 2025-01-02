package com.ascendpgp.customerlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;

import java.time.Duration;

@Configuration
public class Resilience4jConfig {

    // Customize default settings for circuit breakers
    public CircuitBreakerConfig defaultCircuitBreakerConfig() {
        return CircuitBreakerConfig.custom()
                .failureRateThreshold(50) // 50% failure rate to trigger breaker
                .waitDurationInOpenState(Duration.ofSeconds(10)) // Time to wait before retrying
                .slidingWindowSize(5) // Number of calls to calculate failure rate
                .build();
    }

    public TimeLimiterConfig defaultTimeLimiterConfig() {
        return TimeLimiterConfig.custom()
                .timeoutDuration(Duration.ofSeconds(2)) // API timeout duration
                .build();
    }
    
    @Bean
    public RetryConfig retryConfig() {
        return RetryConfig.custom()
                .maxAttempts(3)
                .waitDuration(Duration.ofMillis(500))
                .build();
    }
}