package com.ascendpgp.customerlogin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;

@RestController
@RequestMapping("/api/customer/token")
public class TokenController {
	
	    @Autowired
	    private BlacklistedTokenRepository blacklistedTokenRepository;

	    @GetMapping("/validate")
	    public ResponseEntity<?> validateToken(@RequestParam("token") String token) {
	        boolean isBlacklisted = blacklistedTokenRepository.existsByToken(token);
	        if (isBlacklisted) {
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid or blacklisted.");
	        }
	        return ResponseEntity.ok("Token is valid.");
	    }
}
