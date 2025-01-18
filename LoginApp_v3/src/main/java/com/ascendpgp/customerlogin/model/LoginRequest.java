package com.ascendpgp.customerlogin.model;

import java.util.Base64;

public class LoginRequest {
    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        try {
            // Store the original password
            this.password = password;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid password format");
        }
    }

    public String getDecodedPassword() {
        try {
            return new String(Base64.getDecoder().decode(this.password));
        } catch (Exception e) {
            return this.password; // Return original if not Base64
        }
    }
}