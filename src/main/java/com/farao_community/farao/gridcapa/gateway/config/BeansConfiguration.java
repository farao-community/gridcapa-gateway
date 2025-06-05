/*
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.farao_community.farao.gridcapa.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.web.reactive.function.client.WebClient.Builder;

/**
 * @author Vincent Bochet {@literal <vincent.bochet at rte-france.com>}
 */
@Configuration
public class BeansConfiguration {

    @Bean
    public WebClient webClient(final Builder builder) {
        return builder.build();
    }
}
