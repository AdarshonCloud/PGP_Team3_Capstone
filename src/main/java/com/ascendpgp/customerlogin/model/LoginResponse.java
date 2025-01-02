package com.ascendpgp.customerlogin.model;

import java.util.List;

public class LoginResponse {
    private String token;
    private CustomerEntity.Name name; // Replaced firstName and lastName with Name structure
    private boolean accountValidated;
    private boolean passwordExpired;
    private List<ApiEndpoint> availableEndpoints;
    private String message;

    // Getters and Setters
    
    public String getMessage() { 
        return message;
    }

    public void setMessage(String message) { 
        this.message = message;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public CustomerEntity.Name getName() {
        return name;
    }

    public void setName(CustomerEntity.Name name) {
        this.name = name;
    }

    public boolean isAccountValidated() {
        return accountValidated;
    }

    public void setAccountValidated(boolean accountValidated) {
        this.accountValidated = accountValidated;
    }

    public boolean isPasswordExpired() {
        return passwordExpired;
    }

    public void setPasswordExpired(boolean passwordExpired) {
        this.passwordExpired = passwordExpired;
    }

    public List<ApiEndpoint> getAvailableEndpoints() {
        return availableEndpoints;
    }

    public void setAvailableEndpoints(List<ApiEndpoint> availableEndpoints) {
        this.availableEndpoints = availableEndpoints;
    }
}