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
 * Enumeration of the SAML URL Encoding values.
 * <p>
 * SAML v2 URL Encoding schemes as described in section 3.4.4 of the SAML v2.0 SAML Bindings
 *
 * @author Daniel DeGroff
 * @see <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf</a>
 */
public enum URLEncoding {
  /**
   * Deflate compression encoding. See section 3.4.4.1 of the SAML Bindings specification.
   */
  Deflate("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE");

  /**
   * The SAML String.
   */
  private final String samlFormat;

  URLEncoding(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  /**
   * Locates the URL Encoding using the given SAML String. This is the value from the StatusCode element's value.
   *
   * @param samlFormat The SAML string.
   * @return The URL encoding enum instance.
   * @throws IllegalArgumentException If the samlFormat String is not a valid name ID format.
   */
  public static URLEncoding fromSAMLFormat(String samlFormat) {
    if (samlFormat == null) {
      return null;
    }

    for (URLEncoding nameID : URLEncoding.values()) {
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
