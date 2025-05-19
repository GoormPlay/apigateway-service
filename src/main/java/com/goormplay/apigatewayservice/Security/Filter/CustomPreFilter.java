package com.goormplay.apigatewayservice.Security.Filter;


import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.logging.Logger;

@Component
public class CustomPreFilter implements GlobalFilter, Ordered {

    private static final Logger logger =Logger.getLogger(CustomPreFilter.class.getName());

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
       ServerHttpRequest request = exchange.getRequest();
       logger.info("======Pre Filter======");
       logger.info("PreFilter :  URI       -> " + request.getURI());
       logger.info("PreFilter :  Method:   -> " + request.getMethod());
        logger.info("PreFilter :  Headers:  -> " + request.getHeaders());
        logger.info("PreFilter :  Added X-From-Gateway: true");

        ServerHttpRequest modifiedRequest = request.mutate()
                .header("X-From-Gateway", "true")
                .build();
        //요청이 gateway를 지났음을 header에 담음

       return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
