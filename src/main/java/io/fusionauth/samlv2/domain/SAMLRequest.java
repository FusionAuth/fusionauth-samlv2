/*
 * Copyright (c) 2021-2024, Inversoft Inc., All Rights Reserved
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
 * The SAML v2.0 request object.
 *
 * @author Brian Pontarelli
 */
public class SAMLRequest {
  public String destination;

  public String id;

  public ZonedDateTime issueInstant;

  public String issuer;

  public String version;

  public String xml;

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SAMLRequest that = (SAMLRequest) o;
    return Objects.equals(destination, that.destination) &&
        Objects.equals(id, that.id) &&
        Objects.equals(issueInstant, that.issueInstant) &&
        Objects.equals(issuer, that.issuer) &&
        Objects.equals(version, that.version) &&
        Objects.equals(xml, that.xml);
  }

  @Override
  public int hashCode() {
    return Objects.hash(destination, id, issueInstant, issuer, version, xml);
  }
}
