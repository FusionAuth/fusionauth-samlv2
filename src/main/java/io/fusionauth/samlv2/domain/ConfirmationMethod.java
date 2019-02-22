/*
 * Copyright (c) 2013, Inversoft Inc., All Rights Reserved
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
 * Enumeration of the SAML v2.0 subject confirmation types.
 *
 * @author Brian Pontarelli
 */
public enum ConfirmationMethod {
  /**
   * The subject of the assertion is the bearer of the assertion, subject to optional constraints on confirmation using
   * the attributes that MAY be present in the &lt;SubjectConfirmationData> element, as defined by [SAMLCore].
   */
  Bearer("urn:oasis:names:tc:SAML:2.0:cm:bearer"),

  /**
   * One or more &lt;ds:KeyInfo> elements MUST be present within the &lt;SubjectConfirmationData> element. An xsi:type
   * attribute MAY be present in the &lt;SubjectConfirmationData> element and, if present, MUST be set to
   * saml:KeyInfoConfirmationDataType (the namespace prefix is arbitrary but must reference the SAML assertion
   * namespace).
   * <p/>
   * As described in [XMLSig], each &lt;ds:KeyInfo> element holds a key or information that enables an application to
   * obtain a key. The holder of a specified key is considered to be the subject of the assertion by the asserting
   * party.
   * <p/>
   * Note that in accordance with [XMLSig], each &lt;ds:KeyInfo> element MUST identify a single cryptographic key.
   * Multiple keys MAY be identified with separate &lt;ds:KeyInfo> elements, such as when different confirmation keys
   * are needed for different relying parties.
   */
  HolderOfKey("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"),

  /**
   * Indicates that no other information is available about the context of use of the assertion. The relying party
   * SHOULD utilize other means to determine if it should process the assertion further, subject to optional constraints
   * on confirmation using the attributes that MAY be present in the &lt;SubjectConfirmationData> element, as defined by
   * [SAMLCore].
   */
  SenderVouches("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");

  /**
   * The SAML string.
   */
  private final String samlFormat;

  private ConfirmationMethod(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  /**
   * Locates the ConfirmationMethod using the given SAML String. This is the value from the StatusCode element's value.
   *
   * @param samlFormat The SAML string.
   * @return The ConfirmationMethod enum instance.
   * @throws IllegalArgumentException If the samlFormat String is not a valid status code.
   */
  public static ConfirmationMethod fromSAMLFormat(String samlFormat) {
    if (samlFormat == null) {
      return null;
    }

    for (ConfirmationMethod method : ConfirmationMethod.values()) {
      if (method.toSAMLFormat().equals(samlFormat)) {
        return method;
      }
    }

    throw new IllegalArgumentException("Invalid SAML v2.0 confirmation method [" + samlFormat + "]");
  }

  public String toSAMLFormat() {
    return samlFormat;
  }
}
