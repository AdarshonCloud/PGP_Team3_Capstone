package com.ascendpgp.creditcard.config;

import com.ascendpgp.creditcard.filters.JwtAuthenticationFilter;
import com.ascendpgp.creditcard.utils.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http, RestTemplate restTemplate) throws Exception {
        http
                .sessionManagement(session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .csrf(csrf -> csrf.disable())  // CSRF Disabled
                .authorizeHttpRequests(auth -> auth
                                .requestMatchers(
                                        "/v3/api-docs/**",
                                        "/swagger-ui/**",
                                        "/swagger-ui.html",
                                        "/error"
                                ).permitAll()
                                .anyRequest().authenticated() // All other endpoints require authentication
                )
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtService, null, restTemplate), // CSRF token repository removed
                        UsernamePasswordAuthenticationFilter.class
                );

        logger.info("Security Filter Chain configured successfully with CSRF disable and token validation.");
        return http.build();
    }
}