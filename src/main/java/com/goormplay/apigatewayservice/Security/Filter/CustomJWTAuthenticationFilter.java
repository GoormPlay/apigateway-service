package com.goormplay.apigatewayservice.Security.Filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
public class CustomJWTAuthenticationFilter implements GlobalFilter {

    @Value("${service.jwt.secret-key}")
    private String secretKey;

    @Value("#{'${security.permit-paths}'.split(',')}")//yml에 리스트로 만들어봄
    private List<String> permitPaths;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("Filter 시작");
        // public 요청은 토큰 검증 스킵
        if ("true".equals(exchange.getRequest().getHeaders().getFirst("X-Public-Request"))) {
            return chain.filter(exchange);
        }
        String path = exchange.getRequest().getURI().getPath();
        String originalPath = exchange.getRequest().getHeaders().getFirst("X-Original-Path");
        if (originalPath != null && isPermittedPath(originalPath)) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        log.info("AccessToken:   "+ token);
        if (token == null || !validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private boolean isPermittedPath(String currentPath) {
        log.info("현재 요청 -> " + currentPath);
        log.info("허용된 경로들 -> " + permitPaths); // 실제 로드된 permitPaths 확인

        return permitPaths.stream()
                .peek(permitPath -> log.info("checking path: " + permitPath)) // 각 permitPath 체크 로깅
                .filter(permitPath ->
                        PathPatternParser.defaultInstance.parse(permitPath).matches(PathContainer.parsePath(currentPath))
                )
                .findFirst()
                .map(matchedPath -> {
                    log.info("매치된 permitPath: " + matchedPath);
                    return true;
                })
                .orElse(false);
    }

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {//사용 라이브러리 변경
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey); // secretKey는 String 또는 byte[]
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            log.info("페이로드: " + jwt.getPayload());
            return true;
        } catch (JWTVerificationException exception) {
            // 서명 오류, 만료, 클레임 오류 등
            log.error("유효하지 않은 JWT 토큰입니다: " + exception.getMessage());
            return false;
        }
    }


}