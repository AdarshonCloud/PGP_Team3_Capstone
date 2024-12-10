package com.ascendpgp.customerlogin.model;

import java.util.List;

public class LoginResponse {
    private String token;
    private String firstName;
    private String lastName;
    private boolean accountValidated;
    private boolean passwordExpired;
    private List<ApiEndpoint> availableEndpoints;  // Add this field

    // Getters and Setters

    public boolean isPasswordExpired() {
        return passwordExpired;
    }

    public void setPasswordExpired(boolean passwordExpired) {
        this.passwordExpired = passwordExpired;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public boolean isAccountValidated() {
        return accountValidated;
    }

    public void setAccountValidated(boolean accountValidated) {
        this.accountValidated = accountValidated;
    }

    public List<ApiEndpoint> getAvailableEndpoints() {
        return availableEndpoints;
    }

    public void setAvailableEndpoints(List<ApiEndpoint> availableEndpoints) {
        this.availableEndpoints = availableEndpoints;
    }
}

