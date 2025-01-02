package com.ascendpgp.customerlogin.config;

import com.ascendpgp.customerlogin.config.JwtAuthenticationFilter;
import com.ascendpgp.customerlogin.utils.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .disable()) // Disable CSRF protection
            .authorizeHttpRequests(auth -> auth
            		.requestMatchers("/api/customer/logout").authenticated()  // Protect logout
                // Permit public endpoints
                .requestMatchers(
                    "/api/customer/login",
                    "/api/customer/login/subsequent",
                    "/api/customer/forgot-password/**",
                    "/api/customer/verify",
                    "/api/customer/jwt/validate",
                    "/api/customer/token/validate",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**"
                ).permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Use stateless sessions
            .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}