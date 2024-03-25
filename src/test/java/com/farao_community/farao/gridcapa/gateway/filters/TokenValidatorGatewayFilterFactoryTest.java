/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway.filters;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;

/**
 * @author Vincent Bochet {@literal <vincent.bochet at rte-france.com>}
 */
@SpringBootTest
class TokenValidatorGatewayFilterFactoryTest {
    private static final String JWT_WITH_UNKNOWN_ISSUER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJ1bmtub3duIiwiYXVkIjoiY2xpZW50SWQifQ.SaohF7FRNt30JxWoAN2fNdrpBsz2jqJZyovhtszOPJI";
    private static final String JWT_WITH_KNOWN_ISSUER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L3Rlc3QvaXNzdWVyIiwiYXVkIjoiY2xpZW50SWQifQ.xW-ssMFwQLCdOVofwFkAo8QyR5UCGRyoWxICCzrg2y8";

    private final String jwkSetUri = "http://localhost/test/jwk-set";

    @InjectMocks
    private TokenValidatorGatewayFilterFactory filterFactory;
    @Mock
    private RestTemplate restTemplate;

    @BeforeEach
    private void setValues() {
        ReflectionTestUtils.setField(filterFactory, "jwkSetUri", jwkSetUri);
        ReflectionTestUtils.setField(filterFactory, "issuerBaseUri", "http://localhost/test/issuer");
    }

    @Test
    void applyTest() {
        GatewayFilter gatewayFilter = filterFactory.apply(new Object());

        Assertions.assertThat(gatewayFilter).isNotNull();
    }

    @Test
    void completeWithCodeStandardTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "").body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();

        filterFactory.completeWithCode(exchange, HttpStatus.I_AM_A_TEAPOT);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.I_AM_A_TEAPOT);
        Assertions.assertThat(response.getHeaders().getConnection()).isEmpty();
    }

    @Test
    void completeWithCodeWebsocketTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .header("Upgrade", "websocket")
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();

        filterFactory.completeWithCode(exchange, HttpStatus.I_AM_A_TEAPOT);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.I_AM_A_TEAPOT);
        Assertions.assertThat(response.getHeaders().getConnection()).containsExactly("close");
    }

    @Test
    void filterWithNoAuthTokenTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "").body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void filterWithBadAuthorizationHeaderTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .header("Authorization", "bad_value")
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void filterWithInvalidJwtFromHeaderTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .header("Authorization", "Bearer bad_jwt")
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithInvalidJwtFromQueryParamTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", "bad_jwt")
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithUnknownJwtIssuerTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", JWT_WITH_UNKNOWN_ISSUER)
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithJwkSetParseErrorTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        Mockito.when(restTemplate.getForObject(Mockito.any(), Mockito.any())).thenReturn("invalid_jwkset");

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void filterWithValidJwkSetButInvalidJwtTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        Mockito.when(restTemplate.getForObject(jwkSetUri, String.class)).thenReturn("{\"keys\":[{\"kid\":\"test_kid\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"test_n\",\"e\":\"AQAB\",\"x5t\":\"test_x5t\",\"x5t#S256\":\"test_x5t#S256\"}]}");

        filterFactory.filter(exchange, filterChain);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithOutdatedCacheTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain filterChain = Mockito.mock(GatewayFilterChain.class);

        Mockito.when(restTemplate.getForObject(jwkSetUri, String.class)).thenReturn("{\"keys\":[{\"kid\":\"test_kid\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"test_n\",\"e\":\"AQAB\",\"x5t\":\"test_x5t\",\"x5t#S256\":\"test_x5t#S256\"}]}");

        filterFactory.filter(exchange, filterChain); // Once to initialize the cache
        filterFactory.filter(exchange, filterChain); // Once to test the cache refresh

        Mockito.verify(restTemplate, Mockito.times(2)).getForObject(jwkSetUri, String.class);

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // Too difficult to test a passing case without revealing sensitive data about JWT or JWKSet
    // Will test the setHeaderUserId method directly
    @Test
    void setHeaderUserIdTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "")
            .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
            .body("");
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        String userId = "TheFabPotatoe";

        TokenValidatorGatewayFilterFactory.setHeaderUserId(exchange, userId);

        Assertions.assertThat(request.getHeaders().get("userId")).containsExactly(userId);
    }
}
