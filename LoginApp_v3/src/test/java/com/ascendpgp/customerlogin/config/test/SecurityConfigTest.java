package com.ascendpgp.customerlogin.config.test;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import com.ascendpgp.customerlogin.config.SecurityConfig;
import com.ascendpgp.customerlogin.controller.CustomerController;
import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@WebMvcTest(CustomerController.class)
@Import({SecurityConfig.class})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CustomerService customerService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private CustomerRepository customerRepository;

    @MockBean
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Test
    void testPublicEndpoint() throws Exception {
        when(customerService.login(any(), eq(false))).thenReturn(null);

        mockMvc.perform(post("/api/customer/login/subsequent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
                        .content("{\"email\":\"test@example.com\",\"password\":\"cGFzc3dvcmQxMjM=\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    void testProtectedEndpoint() throws Exception {
        mockMvc.perform(post("/api/customer/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
                        .content("{\"currentPassword\":\"old\",\"newPassword\":\"new\",\"confirmPassword\":\"new\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void testProtectedEndpointWithoutAuth() throws Exception {
        mockMvc.perform(post("/api/customer/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
                        .content("{\"currentPassword\":\"old\",\"newPassword\":\"new\",\"confirmPassword\":\"new\"}"))
                .andExpect(status().isForbidden());
    }
}