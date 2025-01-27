package com.ascendpgp.creditcard.config;

import com.ascendpgp.creditcard.filters.JwtAuthenticationFilter;
import com.ascendpgp.creditcard.utils.JwtService;

import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                      RestTemplate restTemplate,
                                                      @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping) throws Exception  {
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
                                "/actuator/**",
                                "/error"
                        ).permitAll()
                        .requestMatchers("/api/customer/token/validate").authenticated()
                        .anyRequest().authenticated()) // All other endpoints require authentication
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtService, null, restTemplate, handlerMapping), // CSRF token repository removed
                        UsernamePasswordAuthenticationFilter.class
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType("application/json");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("{\"error\": \"Unauthorized: Missing or invalid Authorization header\"}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setContentType("application/json");
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().write("{\"error\": \"Forbidden: Access denied\"}");
                        })
                );

        logger.info("Security Filter Chain configured successfully with CSRF disable and token validation.");
        return http.build();
    }
}