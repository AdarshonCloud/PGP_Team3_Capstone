package com.ascendpgp.creditcard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

	 @Override
	    public void addCorsMappings(CorsRegistry registry) {
	        registry.addMapping("/**") // Allow all endpoints
	        		.allowedOrigins("http://localhost:3000") // Allow frontend domains
	                .allowedOrigins("http://localhost:8083") // Allow Swagger UI origin
	                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH") // Allow these HTTP methods
	                .allowedHeaders("*") // Allow all headers
	                .exposedHeaders("Authorization", "X-CSRF-TOKEN") // Ensure headers like JWT or CSRF are exposed
	                .allowCredentials(true); // Allow cookies/credentials
	    }
}