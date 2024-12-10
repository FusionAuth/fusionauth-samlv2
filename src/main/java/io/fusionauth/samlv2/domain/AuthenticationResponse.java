/*
 * Copyright (c) 2013-2024, Inversoft Inc., All Rights Reserved
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
import java.util.Objects;

/**
 * The SAML v2.0 authentication response object that is sent back from the IDP.
 *
 * @author Brian Pontarelli
 */
public class AuthenticationResponse extends SAMLResponse {
  public Assertion assertion = new Assertion();

  public String rawResponse;

  public ZonedDateTime sessionExpiry;

  public String sessionIndex;

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
    return Objects.equals(assertion, that.assertion) &&
        Objects.equals(sessionExpiry, that.sessionExpiry) &&
        Objects.equals(sessionIndex, that.sessionIndex);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), assertion, rawResponse, sessionExpiry, sessionIndex);
  }
}
