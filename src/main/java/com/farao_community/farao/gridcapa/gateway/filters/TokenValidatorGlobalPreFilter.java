/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway.filters;

import com.farao_community.farao.gridcapa.gateway.GatewayService;
import com.farao_community.farao.gridcapa.gateway.dto.TokenIntrospection;
import com.farao_community.farao.gridcapa.gateway.exceptions.IncorrectAuthorizationHeaderException;
import com.farao_community.farao.gridcapa.gateway.exceptions.NoAccessTokenFoundInQueryException;
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
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

@Component
public class TokenValidatorGlobalPreFilter extends AbstractGlobalPreFilter {

    private static final String UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING = "{}: 401 Unauthorized, Invalid plain JOSE object encoding or inactive opaque token";
    private static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted";
    private static final String PARSING_ERROR = "{}: 500 Internal Server Error, error has been reached unexpectedly while parsing";
    private static final String CACHE_OUTDATED = "{}: Bad JSON Object Signing and Encryption, cache outdated";

    private static final String HEADER_USER_ID = "userId";
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerBaseUri;

    private JWKSet jwkSetCache = null;

    private final GatewayService gatewayService;

    public TokenValidatorGlobalPreFilter(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 4;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        String token;
        try {
            token = extractAccessToken(exchange.getRequest());
        } catch (NoAccessTokenFoundInQueryException | IncorrectAuthorizationHeaderException e) {
            LOGGER.info("{}: 400 Bad Request, incorrect Authorization header value", exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.BAD_REQUEST);
        }

        try {
            return handleTokenAsJwt(token, exchange, chain);
        } catch (ParseException e) {
            // Invalid plain JOSE object encoding
            LOGGER.debug("JWTParser.parse ParseException, will attempt to use as opaque token: ({})", e.getMessage());
            return handleTokenAsOpaqueToken(token, exchange, chain);
        }
    }

    private static String extractAccessToken(ServerHttpRequest request) throws NoAccessTokenFoundInQueryException, IncorrectAuthorizationHeaderException {
        List<String> authorizationHeaderList = request.getHeaders().get("Authorization");
        List<String> accessTokenQueryList = request.getQueryParams().get("access_token");

        if (isAccessTokenAbsentFromRequest(authorizationHeaderList, accessTokenQueryList)) {
            throw new NoAccessTokenFoundInQueryException();
        }

        if (authorizationHeaderList != null) {
            String authorization = authorizationHeaderList.get(0);
            List<String> splitAuthorization = Arrays.asList(authorization.split(" "));

            if (splitAuthorization.size() != 2 || !splitAuthorization.get(0).equals("Bearer")) {
                throw new IncorrectAuthorizationHeaderException();
            }

            return splitAuthorization.get(1);
        } else {
            return accessTokenQueryList.get(0);
        }
    }

    private static boolean isAccessTokenAbsentFromRequest(List<String> authorizationHeaderList, List<String> accessTokenQueryList) {
        boolean bothNull = authorizationHeaderList == null && accessTokenQueryList == null;
        boolean queryNullAndHeaderEmpty = authorizationHeaderList != null && accessTokenQueryList == null && authorizationHeaderList.isEmpty();
        boolean headerNullAndQueryEmpty = authorizationHeaderList == null && accessTokenQueryList != null && accessTokenQueryList.isEmpty();
        boolean bothEmpty = authorizationHeaderList != null && accessTokenQueryList != null && accessTokenQueryList.isEmpty() && authorizationHeaderList.isEmpty();

        return bothNull || queryNullAndHeaderEmpty || headerNullAndQueryEmpty || bothEmpty;
    }

    private Mono<Void> handleTokenAsJwt(String token, ServerWebExchange exchange, GatewayFilterChain chain) throws ParseException {
        JWT jwt = JWTParser.parse(token);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        ClientID clientID = new ClientID(jwtClaimsSet.getAudience().get(0));
        JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());

        LOGGER.debug("checking issuer");
        if (!jwtClaimsSet.getIssuer().startsWith(issuerBaseUri)) {
            LOGGER.info("{}: 401 Unauthorized, Issuer is not allowed: {}", exchange.getRequest().getPath(), jwtClaimsSet.getIssuer());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        return getJwksAndValidateTokenAndSetHeaderUserId(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, clientID, jwsAlg));
    }

    private Mono<Void> getJwksAndValidateTokenAndSetHeaderUserId(FilterInfos filterInfos) {
        if (jwkSetCache == null) {
            try {
                addJwkSetToCache();
            } catch (ParseException e) {
                LOGGER.info(PARSING_ERROR, filterInfos.exchange().getRequest().getPath());
                return completeWithCode(filterInfos.exchange(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }

        try {
            validateJwt(filterInfos);
        } catch (JOSEException | BadJOSEException e) {
            return handleValidationException(filterInfos, e);
        }

        setHeaderUserId(filterInfos.exchange(), filterInfos.jwtClaimsSet().getSubject());

        return filterInfos.chain().filter(filterInfos.exchange());
    }

    private void addJwkSetToCache() throws ParseException {
        String jwkSetUri = gatewayService.getJwkSetUri(issuerBaseUri);
        String jwkSetString = gatewayService.getJwkSet(jwkSetUri);
        jwkSetCache = JWKSet.parse(jwkSetString);
    }

    private void validateJwt(FilterInfos filterInfos) throws BadJOSEException, JOSEException {
        // Create validator for signed ID tokens
        // this works with jwt access tokens too (by chance ?) Do we need to modify this ?
        Issuer issuer = new Issuer(issuerBaseUri);
        IDTokenValidator validator = new IDTokenValidator(issuer, filterInfos.clientID(), filterInfos.jwsAlg(), jwkSetCache);
        validator.validate(filterInfos.jwt(), null);

        // we can safely trust the JWT
        LOGGER.debug("JWT Token verified, it can be trusted");
    }

    private Mono<Void> handleValidationException(FilterInfos filterInfos, Exception e) {
        if (e instanceof BadJOSEException && jwkSetCache != null) {
            LOGGER.info(CACHE_OUTDATED, filterInfos.exchange().getRequest().getPath());
            jwkSetCache = null;
            return this.getJwksAndValidateTokenAndSetHeaderUserId(filterInfos);
        } else {
            LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.exchange().getRequest().getPath());
            return completeWithCode(filterInfos.exchange(), HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> handleTokenAsOpaqueToken(String token, ServerWebExchange exchange, GatewayFilterChain chain) {
        String opaqueTokenIntrospectionUri = gatewayService.getOpaqueTokenIntrospectionUri(issuerBaseUri);
        TokenIntrospection tokenIntrospection = gatewayService.getOpaqueTokenIntrospection(opaqueTokenIntrospectionUri, token);

        setHeaderUserId(exchange, tokenIntrospection.getClientId());

        if (tokenIntrospection.getActive()) {
            LOGGER.debug("Opaque Token verified, it can be trusted");
            return chain.filter(exchange);
        } else {
            LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private static void setHeaderUserId(ServerWebExchange exchange, String userId) {
        exchange.getRequest()
            .mutate()
            .headers(h -> h.set(HEADER_USER_ID, userId));
    }

    private record FilterInfos(ServerWebExchange exchange,
                               GatewayFilterChain chain,
                               JWT jwt,
                               JWTClaimsSet jwtClaimsSet,
                               ClientID clientID,
                               JWSAlgorithm jwsAlg) {
    }
}
