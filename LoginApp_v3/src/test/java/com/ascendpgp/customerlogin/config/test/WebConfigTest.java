package com.ascendpgp.customerlogin.config.test;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
class WebConfigTest {

    @Autowired
    private MockMvc mockMvc;

//    @Test
//    void testCorsConfiguration() throws Exception {
//        mockMvc.perform(options("/api/test")
//                        .header("Origin", "http://localhost:3000")
//                        .header("Access-Control-Request-Method", "GET"))
//                .andExpect(status().isOk())
//                .andExpect(header().exists("Access-Control-Allow-Origin"))
//                .andExpect(header().exists("Access-Control-Allow-Methods"))
//                .andExpect(header().exists("Access-Control-Allow-Headers"));
//    }
}

class CorsConfigTest {

    @Autowired
    private MockMvc mockMvc;

//    @Test
//    void testCorsFilter() throws Exception {
//        mockMvc.perform(options("/api/test")
//                        .header("Origin", "*"))
//                .andExpect(status().isOk())
//                .andExpect(header().string("Access-Control-Allow-Origin", "*"))
//                .andExpect(header().exists("Access-Control-Allow-Methods"))
//                .andExpect(header().exists("Access-Control-Allow-Headers"));
//    }
}