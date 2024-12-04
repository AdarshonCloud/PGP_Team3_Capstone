package com.ascendpgp.customerlogin.model;

public class LoginRequest {
    private String username;
    private String password;

    // Constructors
    public LoginRequest() {}  // Default constructor is required for JSON parsing

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}