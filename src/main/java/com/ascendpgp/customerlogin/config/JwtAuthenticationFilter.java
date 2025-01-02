package com.ascendpgp.customerlogin.config;

import java.io.IOException;
import java.util.ArrayList;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ascendpgp.customerlogin.utils.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Skip filtering for endpoints that don't require authentication.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Skip filtering for public endpoints
        return path.equals("/api/customer/login") ||
                path.equals("/api/customer/login/subsequent") ||
                path.startsWith("/api/customer/forgot-password") ||
                path.equals("/api/customer/verify") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        // If no token is provided, continue the filter chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // Extract the token

        try {
            // Validate the token
            if (jwtService.validateToken(token)) {
                // Extract username from the token
                String username = jwtService.extractUsername(token);

                if (username != null) {
                    // Create UserDetails for authentication
                    User principal = new User(username, "", new ArrayList<>());

                    // Set up authentication in the SecurityContext
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(principal, null, new ArrayList<>());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } else {
                throw new RuntimeException("Invalid JWT token");
            }

        } catch (Exception e) {
            // Log the invalid token
            System.out.println("Invalid JWT token: " + e.getMessage());
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}