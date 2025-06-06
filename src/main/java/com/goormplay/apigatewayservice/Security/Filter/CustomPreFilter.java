package com.goormplay.apigatewayservice.Security.Filter;


import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.logging.Logger;

@Component
public class CustomPreFilter implements GlobalFilter, Ordered {

    private static final Logger logger =Logger.getLogger(CustomPreFilter.class.getName());

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String originalPath = request.getPath().pathWithinApplication().value();  // 예: /api/public/contents/latest
        String[] permittedPaths = {"/api/public/", "/api/auth"};

        // public 요청 여부 판단
        boolean isPublic = Arrays.stream(permittedPaths)
                .anyMatch(originalPath::startsWith);

        logger.info("======Pre Filter======");
        logger.info("PreFilter :  URI       -> " + request.getURI());
        logger.info("PreFilter :  Method    -> " + request.getMethod());
        logger.info("PreFilter :  Headers   -> " + request.getHeaders());
        logger.info("PreFilter :  Original Path for JWT check -> " + originalPath);

        // ✅ 헤더를 .headers() 방식으로 추가
        ServerHttpRequest modifiedRequest = request.mutate()
                .header("X-From-Gateway", "true")
                .header("X-Public-Request", isPublic ? "true" : "false")
                .header("X-Original-Path", originalPath)
                .build();
        //요청이 gateway를 지났음을 header에 담음

       return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
