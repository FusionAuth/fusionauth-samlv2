/*
 * Copyright (c) 2021-2025, Inversoft Inc., All Rights Reserved
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
 * The SAML v2.0 response object.
 *
 * @author Daniel DeGroff
 */
public class SAMLResponse extends SAMLRequest {
  public ZonedDateTime authnInstant;

  public String inResponseTo;

  public Status status = new Status();

  public SAMLResponse() {
  }

  public SAMLResponse(SAMLResponse other) {
    super(other);
    this.authnInstant = other.authnInstant;
    this.inResponseTo = other.inResponseTo;
    this.status = new Status(other.status);
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
    SAMLResponse that = (SAMLResponse) o;
    return Objects.equals(authnInstant, that.authnInstant) &&
        Objects.equals(inResponseTo, that.inResponseTo) &&
        Objects.equals(status, that.status);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), authnInstant, inResponseTo, status);
  }
}
