/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway.filters;

import com.farao_community.farao.gridcapa.gateway.exceptions.TokenExtractionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

/**
 * @author Vincent Bochet {@literal <vincent.bochet at rte-france.com>}
 * @author Daniel Thirion {@literal <daniel.thirion at rte-france.com>}
 */
@Component
public class TokenValidatorGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    private static final String BAD_REQUEST_EXTRACTION_OF_AUTH_TOKEN_FAILED = "{}: 400 Bad Request, extraction of auth token failed";
    private static final String UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING = "{}: 401 Unauthorized, Invalid plain JOSE object encoding";
    private static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted";
    private static final String UNAUTHORIZED_ISSUER_IS_NOT_ALLOWED = "{}: 401 Unauthorized, Issuer is not allowed: {}";
    private static final String PARSING_ERROR = "500 Internal Server Error, error has been reached unexpectedly while parsing";
    private static final String CACHE_OUTDATED = "{}: Bad JSON Object Signing and Encryption, cache outdated";

    private static final String HEADER_USER_ID = "userId";
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGatewayFilterFactory.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerBaseUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    private JWKSet jwkSetCache = null;

    private final WebClient webClient;

    public TokenValidatorGatewayFilterFactory(final WebClient webClient) {
        super(Object.class);
        this.webClient = webClient;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return this::filter;
    }

    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {
        LOGGER.info("Filter : {}", getClass().getSimpleName());

        String token;
        try {
            token = extractAccessToken(exchange.getRequest());
        } catch (TokenExtractionException tee) {
            LOGGER.info(BAD_REQUEST_EXTRACTION_OF_AUTH_TOKEN_FAILED, exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.BAD_REQUEST);
        }

        try {
            return handleTokenAsJwt(token, exchange, chain);
        } catch (ParseException e) {
            // Invalid plain JOSE object encoding
            LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private static String extractAccessToken(ServerHttpRequest request) throws TokenExtractionException {
        List<String> authorizationHeaderList = request.getHeaders().get("Authorization");
        List<String> accessTokenQueryList = request.getQueryParams().get("access_token");

        if (isAccessTokenAbsentFromRequest(authorizationHeaderList, accessTokenQueryList)) {
            throw new TokenExtractionException();
        }

        if (authorizationHeaderList != null) {
            String authorization = authorizationHeaderList.get(0);
            List<String> splitAuthorization = Arrays.asList(authorization.split(" "));

            if (splitAuthorization.size() != 2 || !splitAuthorization.get(0).equals("Bearer")) {
                throw new TokenExtractionException();
            }

            return splitAuthorization.get(1);
        } else {
            return accessTokenQueryList.get(0);
        }
    }

    private static boolean isAccessTokenAbsentFromRequest(List<String> authorizationHeaderList,
                                                          List<String> accessTokenQueryList) {
        boolean bothNull = authorizationHeaderList == null && accessTokenQueryList == null;
        boolean queryNullAndHeaderEmpty = authorizationHeaderList != null && accessTokenQueryList == null && authorizationHeaderList.isEmpty();
        boolean headerNullAndQueryEmpty = authorizationHeaderList == null && accessTokenQueryList != null && accessTokenQueryList.isEmpty();
        boolean bothEmpty = authorizationHeaderList != null && accessTokenQueryList != null && accessTokenQueryList.isEmpty() && authorizationHeaderList.isEmpty();

        return bothNull || queryNullAndHeaderEmpty || headerNullAndQueryEmpty || bothEmpty;
    }

    private Mono<Void> handleTokenAsJwt(String token,
                                        ServerWebExchange exchange,
                                        GatewayFilterChain chain) throws ParseException {
        JWT jwt = JWTParser.parse(token);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        ClientID clientID = new ClientID(jwtClaimsSet.getAudience().get(0));
        JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());

        LOGGER.info("checking issuer");
        if (!jwtClaimsSet.getIssuer().startsWith(issuerBaseUri)) {
            LOGGER.info(UNAUTHORIZED_ISSUER_IS_NOT_ALLOWED, exchange.getRequest().getPath(), jwtClaimsSet.getIssuer());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        return validateTokenAndSetHeaderUserId(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, clientID, jwsAlg));
    }

    private Mono<Void> validateTokenAndSetHeaderUserId(FilterInfos filterInfos) {
        final Mono<Void> cacheMono;

        final boolean cacheWasNull = jwkSetCache == null;
        if (cacheWasNull) {
            cacheMono = addJwkSetToCache();
        } else {
            cacheMono = Mono.empty();
        }

        return cacheMono
                .then(Mono.defer(() -> filterWithValidatedJwt(filterInfos, cacheWasNull)));
    }

    private Mono<Void> filterWithValidatedJwt(final FilterInfos filterInfos,
                                              final boolean cacheWasNull) {
        try {
            validateJwt(filterInfos);
        } catch (JOSEException | BadJOSEException e) {
            return handleValidationException(filterInfos, cacheWasNull, e);
        }
        final ServerWebExchange newExchange = setHeaderUserIdInNewExchange(
                filterInfos.exchange(),
                filterInfos.jwtClaimsSet().getSubject()
        );
        return filterInfos.chain().filter(newExchange);
    }

    private Mono<Void> addJwkSetToCache() {
        return webClient.get()
                .uri(jwkSetUri)
                .retrieve()
                .bodyToMono(String.class)
                .<JWKSet>handle((jwkSetStr, sink) -> {
                    try {
                        sink.next(JWKSet.parse(jwkSetStr));
                    } catch (RuntimeException | ParseException e) {
                        LOGGER.error(PARSING_ERROR, e);
                        sink.error(new JwkSetParsingException(PARSING_ERROR, e));
                    }
                })
                .doOnNext(jwkSet -> jwkSetCache = jwkSet)
                .then()
                .onErrorResume(e -> {
                    LOGGER.error("Impossible to update JWKSet cache : {}", e.getMessage(), e);
                    return Mono.error(e);
                });
    }

    private void validateJwt(FilterInfos filterInfos) throws BadJOSEException, JOSEException {
        // Create validator for signed ID tokens
        // this works with jwt access tokens too (by chance ?) Do we need to modify this ?
        Issuer issuer = new Issuer(issuerBaseUri);
        IDTokenValidator validator = new IDTokenValidator(issuer, filterInfos.clientID(), filterInfos.jwsAlg(), jwkSetCache);
        validator.validate(filterInfos.jwt(), null);

        // we can safely trust the JWT
        LOGGER.info("JWT Token verified, it can be trusted");
    }

    private Mono<Void> handleValidationException(FilterInfos filterInfos,
                                                 boolean cacheRefreshed,
                                                 Exception e) {
        if (e instanceof BadJOSEException && !cacheRefreshed) {
            LOGGER.info(CACHE_OUTDATED, filterInfos.exchange().getRequest().getPath());
            jwkSetCache = null;
            return validateTokenAndSetHeaderUserId(filterInfos);
        } else {
            LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.exchange().getRequest().getPath());
            return completeWithCode(filterInfos.exchange(), HttpStatus.UNAUTHORIZED);
        }
    }

    protected static ServerWebExchange setHeaderUserIdInNewExchange(ServerWebExchange exchange,
                                                                    String userId) {
        final ServerHttpRequest newRequest = exchange.getRequest()
                .mutate()
                .headers(h -> h.set(HEADER_USER_ID, userId))
                .build();
        return exchange.mutate().request(newRequest).build();
    }

    protected Mono<Void> completeWithCode(ServerWebExchange exchange,
                                          HttpStatus code) {
        exchange.getResponse().setStatusCode(code);
        if ("websocket".equalsIgnoreCase(exchange.getRequest().getHeaders().getUpgrade())) {
            // Force the connection to close for websockets handshakes to workaround apache
            // httpd reusing the connection for all subsequent requests in this connection.
            exchange.getResponse().getHeaders().set(HttpHeaders.CONNECTION, "close");
        }
        return exchange.getResponse().setComplete();
    }

    private record FilterInfos(ServerWebExchange exchange,
                               GatewayFilterChain chain,
                               JWT jwt,
                               JWTClaimsSet jwtClaimsSet,
                               ClientID clientID,
                               JWSAlgorithm jwsAlg) {
    }

    private static class JwkSetParsingException extends RuntimeException {
        public JwkSetParsingException(String message,
                                      Throwable cause) {
            super(message, cause);
        }
    }

}
