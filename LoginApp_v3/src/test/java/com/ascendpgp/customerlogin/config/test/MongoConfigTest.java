package com.ascendpgp.customerlogin.config.test;

import com.mongodb.client.MongoClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "spring.data.mongodb.uri=mongodb://localhost:27017/test",
        "spring.data.mongodb.database=test"
})
class MongoConfigTest {

    @Autowired
    private ApplicationContext context;

//    @Test
//    void testMongoClientBeanCreation() {
//        MongoClient mongoClient = context.getBean(MongoClient.class);
//        assertNotNull(mongoClient, "MongoClient bean should be created");
//    }

//    @Test
//    void testDatabaseName() {
//        MongoClient mongoClient = context.getBean(MongoClient.class);
//        assertNotNull(mongoClient.getDatabase("CCMS"), "Should be able to get the configured database");
//    }
}