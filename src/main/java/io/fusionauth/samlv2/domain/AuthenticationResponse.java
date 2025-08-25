/*
 * Copyright (c) 2013-2025, Inversoft Inc., All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package io.fusionauth.samlv2.domain;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The SAML v2.0 authentication response object that is sent back from the IDP.
 *
 * @author Brian Pontarelli
 */
public class AuthenticationResponse extends SAMLResponse {
  public List<Assertion> assertions = new ArrayList<>();

  public String rawResponse;

  public ZonedDateTime sessionExpiry;

  public String sessionIndex;

  public AuthenticationResponse() {
  }

  public AuthenticationResponse(AuthenticationResponse other) {
    super(other);
    this.assertions.addAll(other.assertions.stream().map(Assertion::new).toList());
    this.rawResponse = other.rawResponse;
    this.sessionExpiry = other.sessionExpiry;
    this.sessionIndex = other.sessionIndex;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    AuthenticationResponse that = (AuthenticationResponse) o;
    // The comparison does not include the rawResponse because different raw encoded responses can be parsed into
    // identical domain objects. This is mainly true for responses containing an encrypted assertion
    return Objects.equals(assertions, that.assertions) &&
        Objects.equals(sessionExpiry, that.sessionExpiry) &&
        Objects.equals(sessionIndex, that.sessionIndex);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), assertions, rawResponse, sessionExpiry, sessionIndex);
  }
}
