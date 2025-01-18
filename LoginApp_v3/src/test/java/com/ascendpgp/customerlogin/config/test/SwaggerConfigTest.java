package com.ascendpgp.customerlogin.config.test;

import com.ascendpgp.customerlogin.config.SwaggerConfig;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = SwaggerConfig.class)
class SwaggerConfigTest {

    @Autowired
    private SwaggerConfig swaggerConfig;

    @Test
    void testCustomOpenAPI() {
        OpenAPI openAPI = swaggerConfig.customOpenAPI();

        assertNotNull(openAPI, "OpenAPI configuration should not be null");
        assertNotNull(openAPI.getComponents(), "Components should be configured");

        SecurityScheme securityScheme = openAPI.getComponents().getSecuritySchemes().get("bearerAuth");
        assertNotNull(securityScheme, "Bearer auth security scheme should be configured");
        assertEquals(SecurityScheme.Type.HTTP, securityScheme.getType(), "Security scheme type should be HTTP");
        assertEquals("bearer", securityScheme.getScheme(), "Security scheme should be bearer");
        assertEquals("JWT", securityScheme.getBearerFormat(), "Bearer format should be JWT");

        SecurityRequirement requirement = openAPI.getSecurity().get(0);
        assertTrue(requirement.containsKey("bearerAuth"), "Security requirement should include bearerAuth");
    }
}