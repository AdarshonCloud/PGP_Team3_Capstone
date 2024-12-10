package com.ascendpgp.customerlogin.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;
import java.util.List;

@Document(collection = "Customer")
public class CustomerEntity {

    @Id
    private String id;
    private String username;
    private String firstName; 
    private String lastName; 
    private String email;
    private String password;
    private boolean accountValidated;
    private String verificationToken;
    private LocalDateTime verificationTokenExpiry; 
    private String resetPasswordToken;
    private LocalDateTime resetPasswordTokenExpiry;
    private List<String> passwordHistory;
    private boolean firstTimeLogin = true;
    private LocalDateTime passwordExpiryDate;
    private LocalDateTime passwordLastUpdated;

    // Getters and Setters

    public LocalDateTime getPasswordLastUpdated() {
        return passwordLastUpdated;
    }

    public void setPasswordLastUpdated(LocalDateTime passwordLastUpdated) {
        this.passwordLastUpdated = passwordLastUpdated;
    }

    public LocalDateTime getPasswordExpiryDate() {
        return passwordExpiryDate;
    }

    public void setPasswordExpiryDate(LocalDateTime passwordExpiryDate) {
        this.passwordExpiryDate = passwordExpiryDate;
    }
    public LocalDateTime getVerificationTokenExpiry() {
        return verificationTokenExpiry;
    }

    public void setVerificationTokenExpiry(LocalDateTime verificationTokenExpiry) {
        this.verificationTokenExpiry = verificationTokenExpiry;
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

    public boolean isFirstTimeLogin() {
     return firstTimeLogin;
    }

 	public void setFirstTimeLogin(boolean firstTimeLogin) {
     this.firstTimeLogin = firstTimeLogin;
 	}

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

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
        this.password = password;
    }

    public boolean isAccountValidated() {
        return accountValidated;
    }

    public void setAccountValidated(boolean accountValidated) {
        this.accountValidated = accountValidated;
    }

    public String getVerificationToken() {
        return verificationToken;
    }

    public void setVerificationToken(String verificationToken) {
        this.verificationToken = verificationToken;
    }

    public String getResetPasswordToken() {
        return resetPasswordToken;
    }

    public void setResetPasswordToken(String resetPasswordToken) {
        this.resetPasswordToken = resetPasswordToken;
    }

    public LocalDateTime getResetPasswordTokenExpiry() {
        return resetPasswordTokenExpiry;
    }

    public void setResetPasswordTokenExpiry(LocalDateTime resetPasswordTokenExpiry) {
        this.resetPasswordTokenExpiry = resetPasswordTokenExpiry;
    }

    public List<String> getPasswordHistory() {
        return passwordHistory;
    }

    public void setPasswordHistory(List<String> passwordHistory) {
        this.passwordHistory = passwordHistory;
    }

	@Override
	public String toString() {
		return "CustomerEntity [id=" + id + ", username=" + username + ", email=" + email + ", password=" + password
				+ ", accountValidated=" + accountValidated + ", verificationToken=" + verificationToken
				+ ", resetPasswordToken=" + resetPasswordToken + ", resetPasswordTokenExpiry="
				+ resetPasswordTokenExpiry + ", passwordHistory=" + passwordHistory + "]";
	}
    
    
}
