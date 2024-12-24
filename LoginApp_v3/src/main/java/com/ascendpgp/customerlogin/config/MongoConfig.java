package com.ascendpgp.customerlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

@Configuration
public class MongoConfig extends AbstractMongoClientConfiguration {

    @Override
    protected String getDatabaseName() {
        return "CCMS";
    }

    @Bean
    public MongoClient mongoClient() {
        ConnectionString connectionString = new ConnectionString(
            "mongodb+srv://root:q2e0ilmWPlg8cH3Q@ascend.qgdyk.mongodb.net/CCMS?retryWrites=true&w=majority&connectTimeoutMS=60000&socketTimeoutMS=60000&appName=Ascend"
        );
        MongoClientSettings mongoClientSettings = MongoClientSettings.builder()
            .applyConnectionString(connectionString)
            .applyToConnectionPoolSettings(builder ->
                builder.minSize(5).maxSize(100)
            )
            .build();
        return MongoClients.create(mongoClientSettings);
    }
}
