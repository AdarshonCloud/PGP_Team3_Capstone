package com.ascendpgp.creditcard.logging;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.specialized.AppendBlobClient;
import com.azure.storage.blob.specialized.SpecializedBlobClientBuilder;

import ch.qos.logback.core.AppenderBase;

public class AzureBlobAppender extends AppenderBase<Object> {

    private String connectionString;
    private String containerName;
    private String blobName;
    private AppendBlobClient appendBlobClient;

    @Override
    public void start() {
        super.start();
        
        // Only initialize Azure Blob appender if cloud logging is enabled and valid values are provided
        if (connectionString != null && !connectionString.isEmpty() && containerName != null && !containerName.isEmpty()) {
            try {
                // Initialize the Azure Blob service client and get an AppendBlobClient
                BlobContainerClient containerClient = new BlobServiceClientBuilder()
                        .connectionString(connectionString)
                        .buildClient()
                        .getBlobContainerClient(containerName);

                this.appendBlobClient = new SpecializedBlobClientBuilder()
                        .connectionString(connectionString)
                        .containerName(containerName)
                        .blobName(blobName)
                        .buildAppendBlobClient();

                // Create the blob if it doesn't exist
                if (!appendBlobClient.exists()) {
                    appendBlobClient.create();
                }
            } catch (Exception e) {
                addError("Failed to initialize Azure Blob appender", e);
                return;
            }
        } else {
            addInfo("Cloud logging is disabled or invalid connection details provided. Skipping Azure Blob appender initialization.");
        }
    }

    @Override
    protected void append(Object eventObject) {
        if (appendBlobClient != null) {
            String logMessage = eventObject.toString();
            
            // Convert the log message to an InputStream
            try (InputStream inputStream = new ByteArrayInputStream(logMessage.getBytes())) {
                // Append the log message to the blob
                appendBlobClient.appendBlock(inputStream, logMessage.length());
            } catch (Exception e) {
                addError("Failed to append log message to Azure Blob", e);
            }
        }
    }

    // Getters and Setters for connectionString, containerName, and blobName
    public void setConnectionString(String connectionString) {
        this.connectionString = connectionString;
    }

    public void setContainerName(String containerName) {
        this.containerName = containerName;
    }

    public void setBlobName(String blobName) {
        this.blobName = blobName;
    }
}	