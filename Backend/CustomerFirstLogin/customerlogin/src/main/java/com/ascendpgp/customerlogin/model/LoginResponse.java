package com.ascendpgp.customerlogin.model;

public class LoginResponse {
    private String token;
    private String firstName;
    private String lastName;
    private boolean accountValidated;

    // Getters and Setters
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

	@Override
	public String toString() {
		return "LoginResponse [token=" + token + ", firstName=" + firstName + ", lastName=" + lastName
				+ ", accountValidated=" + accountValidated + "]";
	}
    
    
}

