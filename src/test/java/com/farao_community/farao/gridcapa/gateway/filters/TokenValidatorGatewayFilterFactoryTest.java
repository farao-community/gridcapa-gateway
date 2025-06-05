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
import org.mockito.Mockito;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Vincent Bochet {@literal <vincent.bochet at rte-france.com>}
 * @author Daniel Thirion {@literal <daniel.thirion at rte-france.com>}
 */
class TokenValidatorGatewayFilterFactoryTest {

    private static final String JWT_WITH_UNKNOWN_ISSUER =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJ1bmtub3duIiwiYXVkIjoiY2xpZW50SWQifQ.SaohF7FRNt30JxWoAN2fNdrpBsz2jqJZyovhtszOPJI";
    private static final String JWT_WITH_KNOWN_ISSUER =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L3Rlc3QvaXNzdWVyIiwiYXVkIjoiY2xpZW50SWQifQ.xW-ssMFwQLCdOVofwFkAo8QyR5UCGRyoWxICCzrg2y8";
    private static final String DUMMY_JWK_SET =
            "{\"keys\":[{\"kid\":\"test_kid\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"test_n\",\"e\":\"AAAB\"}]}";
    private static final String JWK_SET_URI = "http://localhost/test/jwk-set";

    private WebClient webClient;
    private TokenValidatorGatewayFilterFactory filterFactory;

    @BeforeEach
    void setUp() {
        webClient = Mockito.mock(WebClient.class);
        WebClient.RequestHeadersUriSpec<?> uriSpec = Mockito.mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = Mockito.mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = Mockito.mock(WebClient.ResponseSpec.class);

        Mockito.<WebClient.RequestHeadersUriSpec<?>>when(webClient.get()).thenReturn(uriSpec);
        Mockito.<WebClient.RequestHeadersSpec<?>>when(uriSpec.uri(Mockito.anyString())).thenReturn(headersSpec);
        Mockito.when(headersSpec.retrieve()).thenReturn(responseSpec);
        Mockito.when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(DUMMY_JWK_SET));

        filterFactory = new TokenValidatorGatewayFilterFactory(webClient);
        ReflectionTestUtils.setField(filterFactory, "issuerBaseUri", "http://localhost/test/issuer");
        ReflectionTestUtils.setField(filterFactory, "jwkSetUri", JWK_SET_URI);
    }

    @Test
    void applyTest() {
        Assertions.assertThat(filterFactory.apply(new Object())).isNotNull();
    }

    @Test
    void completeWithCodeStandardTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path").build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();

        filterFactory.completeWithCode(exchange, HttpStatus.BAD_REQUEST).block();

        Assertions.assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void completeWithCodeWebsocketTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .header("Upgrade", "websocket").build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();

        filterFactory.completeWithCode(exchange, HttpStatus.UNAUTHORIZED).block();

        Assertions.assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithNoAuthTokenTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path").build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void filterWithBadAuthorizationHeaderTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .header("Authorization", "Bearer ")
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();
        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void filterWithInvalidJwtFromHeaderTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .header("Authorization", "Bearer fakeValue")
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithInvalidJwtFromQueryParamTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .queryParam("access_token", "fakeValue")
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithUnknownJwtIssuerTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .header("Authorization", "Bearer " + JWT_WITH_UNKNOWN_ISSUER)
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filterWithJwkSetParseErrorTest() {
        setupWebClientJwkSetResponse("invalid response");
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);
        assertThrows(RuntimeException.class, () -> filterFactory.filter(exchange, chain).block());
    }

    @Test
    void filterWithValidJwkSetButInvalidJwtTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .queryParam("access_token", JWT_WITH_KNOWN_ISSUER)
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        filterFactory.filter(exchange, chain).block();

        ServerHttpResponse response = exchange.getResponse();
        Assertions.assertThat(
                response.getStatusCode() == HttpStatus.UNAUTHORIZED ||
                response.getStatusCode() == HttpStatus.BAD_REQUEST
        ).isTrue();
    }

    @Test
    void filterWithOutdatedCacheTest() {
        // JWKset correct in cache but parsing of JWKSet fails
        ReflectionTestUtils.setField(filterFactory, "jwkSetCache", null);
        setupWebClientJwkSetResponse("invalid");

        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path")
                .header("Authorization", "Bearer " + JWT_WITH_KNOWN_ISSUER)
                .build();
        MockServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        GatewayFilterChain chain = Mockito.mock(GatewayFilterChain.class);

        assertThrows(RuntimeException.class, () -> filterFactory.filter(exchange, chain).block());
    }

    @Test
    void setHeaderUserIdInNewExchangeTest() {
        MockServerHttpRequest request = MockServerHttpRequest.method(HttpMethod.GET, "/path").build();
        ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
        String userId = "007";

        ServerWebExchange exchangeWithHeader = TokenValidatorGatewayFilterFactory.setHeaderUserIdInNewExchange(exchange, userId);
        Assertions.assertThat(exchangeWithHeader.getRequest().getHeaders().getFirst("userId")).isEqualTo(userId);
    }

    private void setupWebClientJwkSetResponse(String jwkSetBody) {
        WebClient.RequestHeadersUriSpec<?> uriSpec = Mockito.mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = Mockito.mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = Mockito.mock(WebClient.ResponseSpec.class);

        Mockito.<WebClient.RequestHeadersUriSpec<?>>when(webClient.get()).thenReturn(uriSpec);
        Mockito.<WebClient.RequestHeadersSpec<?>>when(uriSpec.uri(Mockito.anyString())).thenReturn(headersSpec);
        Mockito.when(headersSpec.retrieve()).thenReturn(responseSpec);
        Mockito.when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(jwkSetBody));
    }
}
