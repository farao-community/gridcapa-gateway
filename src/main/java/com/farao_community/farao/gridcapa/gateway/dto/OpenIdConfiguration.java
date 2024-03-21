/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.farao_community.farao.gridcapa.gateway.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;

public class OpenIdConfiguration {
    @JsonAlias("jwks_uri")
    String jwksUri;

    @JsonAlias("introspection_endpoint")
    String introspectionEndpoint;

    @JsonGetter("jwksUri")
    public String getJwksUri() {
        return jwksUri;
    }

    @JsonGetter("introspectionEndpoint")
    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    @JsonSetter("jwksUri")
    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    @JsonSetter("introspectionEndpoint")
    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }
}
