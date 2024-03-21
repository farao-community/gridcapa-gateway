/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway;

import com.farao_community.farao.gridcapa.gateway.dto.OpenIdConfiguration;
import com.farao_community.farao.gridcapa.gateway.dto.TokenIntrospection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class GatewayService {
    private final WebClient.Builder webClientBuilder;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${client_id}")
    private String clientId;

    @Value("${client_secret}")
    private String clientSecret;

    public GatewayService() {
        webClientBuilder = WebClient.builder();
    }

    private Mono<OpenIdConfiguration> getOpenIdConfigurationMono(String issBaseUri) {
        WebClient webClient = webClientBuilder.uriBuilderFactory(new DefaultUriBuilderFactory(issBaseUri)).build();

        String path = UriComponentsBuilder.fromPath("/.well-known/openid-configuration").toUriString();

        return webClient.get()
            .uri(path)
            .retrieve()
            .bodyToMono(OpenIdConfiguration.class)
            .single();
    }

    public String getJwkSetUri(String issBaseUri) {
        return getOpenIdConfigurationMono(issBaseUri)
            .map(OpenIdConfiguration::getJwksUri)
            .block();
    }

    public String getJwkSet(String jwkSetUri) {
        WebClient webClient = webClientBuilder.uriBuilderFactory(new DefaultUriBuilderFactory(jwkSetUri)).build();

        return webClient.get()
                .retrieve()
                .bodyToMono(String.class)
                .single()
                .block();
    }

    public String getOpaqueTokenIntrospectionUri(String issBaseUri) {
        return getOpenIdConfigurationMono(issBaseUri)
                .map(OpenIdConfiguration::getIntrospectionEndpoint)
                .block();
    }

    public TokenIntrospection getOpaqueTokenIntrospection(String introspectionUri, String token) {
        WebClient webClient = webClientBuilder.uriBuilderFactory(new DefaultUriBuilderFactory(introspectionUri)).build();

        return webClient.post()
                .body(BodyInserters
                        .fromFormData("client_id", clientId)
                        .with("client_secret", clientSecret)
                        .with("token", token))
                .retrieve()
                .bodyToMono(TokenIntrospection.class)
                .single()
                .block();
    }
}
