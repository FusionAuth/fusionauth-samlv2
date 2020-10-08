/*
 * Copyright (c) 2013-2019, Inversoft Inc., All Rights Reserved
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

/**
 * Enumeration of the SAML Bindings values.
 * <p>
 * SAML v2 Bindings as described in section 3 of the SAML v2.0 SAML Bindings
 *
 * @author Daniel DeGroff
 * @see <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf</a>
 */
public enum Binding {
  /**
   * HTTP Redirect Binding as described in section 3.4 of the SAML v2.0 Bindings
   */
  HTTP_Redirect("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),

  /**
   * HTTP POST Binding as described in section 3.5 of the SAML v2.0 Bindings
   */
  HTTP_POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

  /**
   * The SAML String.
   */
  private final String samlFormat;

  Binding(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  /**
   * Locates the Binding using the given SAML String. This is the value from the StatusCode element's value.
   *
   * @param samlFormat The SAML string.
   * @return The Binding enum instance.
   * @throws IllegalArgumentException If the samlFormat String is not a valid name ID format.
   */
  public static Binding fromSAMLFormat(String samlFormat) {
    if (samlFormat == null) {
      return null;
    }

    for (Binding nameID : Binding.values()) {
      if (nameID.toSAMLFormat().equals(samlFormat)) {
        return nameID;
      }
    }

    throw new IllegalArgumentException("Invalid SAML v2.0 Bindings [" + samlFormat + "]");
  }

  public String toSAMLFormat() {
    return samlFormat;
  }
}
