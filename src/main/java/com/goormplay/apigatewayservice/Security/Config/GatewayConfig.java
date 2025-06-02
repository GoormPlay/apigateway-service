package com.goormplay.apigatewayservice.Security.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;

import java.util.HashMap;

@Configuration
public class GatewayConfig {
    @Primary
    @Bean
    public SimpleUrlHandlerMapping simpleUrlHandlerMapping() {
        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
        mapping.setOrder(Integer.MAX_VALUE);
        mapping.setUrlMap(new HashMap<>());
        return mapping;
    }
}
