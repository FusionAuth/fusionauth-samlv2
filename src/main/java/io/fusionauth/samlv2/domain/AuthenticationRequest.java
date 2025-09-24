/*
 * Copyright (c) 2019-2025, Inversoft Inc., All Rights Reserved
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

import java.util.Objects;

/**
 * The SAML v2.0 authentication request object that is sent from the SP.
 *
 * @author Brian Pontarelli
 */
public class AuthenticationRequest extends SAMLRequest {
  public String acsURL;

  public Boolean allowCreate = false;

  public Boolean forceAuthn;

  public String nameIdFormat;

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AuthenticationRequest that)) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    return Objects.equals(acsURL, that.acsURL) && Objects.equals(allowCreate, that.allowCreate) && Objects.equals(forceAuthn, that.forceAuthn) && Objects.equals(nameIdFormat, that.nameIdFormat);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), acsURL, allowCreate, forceAuthn, nameIdFormat);
  }
}
