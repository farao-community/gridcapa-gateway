/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;

@Service
public class GatewayService {
    private final WebClient.Builder webClientBuilder;

    public GatewayService() {
        webClientBuilder = WebClient.builder();
    }

    public String getJwkSet(String jwkSetUri) {
        WebClient webClient = webClientBuilder.uriBuilderFactory(new DefaultUriBuilderFactory(jwkSetUri)).build();

        return webClient.get()
                .retrieve()
                .bodyToMono(String.class)
                .single()
                .block();
    }
}
