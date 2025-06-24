package com.goormplay.apigatewayservice.Security.Filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
@Order(-200)
@Component
public class CloudFrontSecretHeaderWebFilter implements WebFilter {
    @Value("${cloudfront.secret}")
    private String secret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String headerValue = exchange.getRequest().getHeaders().getFirst("X-CloudFront-Secret");

        if (!secret.equals(headerValue)) {
            exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.FORBIDDEN);
            byte[] response = "Forbidden: Invalid CloudFront header".getBytes();
            return exchange.getResponse().writeWith(
                    Mono.just(exchange.getResponse().bufferFactory().wrap(response))
            );
        }

        return chain.filter(exchange);
    }
}
