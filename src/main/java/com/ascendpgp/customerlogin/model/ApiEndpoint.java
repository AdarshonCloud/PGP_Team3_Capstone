package com.ascendpgp.customerlogin.model;
import com.ascendpgp.customerlogin.model.ApiEndpoint;

public class ApiEndpoint {
    private String url;
    private String description;

    // Default constructor
    public ApiEndpoint() {
    }

    // Constructor with parameters
    public ApiEndpoint(String url, String description) {
        this.url = url;
        this.description = description;
    }

    // Getters and Setters
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}