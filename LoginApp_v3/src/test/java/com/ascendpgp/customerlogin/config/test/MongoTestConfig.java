// Save as: src/test/java/com/ascendpgp/customerlogin/config/test/MongoTestConfig.java

package com.ascendpgp.customerlogin.config.test;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.MongoTemplate;

import com.ascendpgp.customerlogin.repository.CustomerRepository;

@TestConfiguration
public class MongoTestConfig {

    @Bean
    @Primary
    public MongoTemplate mongoTemplate() {
        return Mockito.mock(MongoTemplate.class);
    }

    @Bean
    @Primary
    public CustomerRepository customerRepository() {
        return Mockito.mock(CustomerRepository.class);
    }
}