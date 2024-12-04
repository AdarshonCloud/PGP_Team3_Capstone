package com.ascendpgp.customerlogin.utils;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final Key SECRET_KEY;

    public JwtService(@Value("${jwt.secret}") String secretKey) {
        if (secretKey == null || secretKey.length() < 32) {
            throw new IllegalArgumentException("JWT Secret key must be at least 32 characters long.");
        }
        this.SECRET_KEY = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

	public String generateToken(String email) {
	    return Jwts.builder()
	            .setSubject(email)
	            .setIssuedAt(new Date())
	            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 48)) // 48 hours
	            .signWith(SECRET_KEY)
	            .compact();
	}

    public String validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

