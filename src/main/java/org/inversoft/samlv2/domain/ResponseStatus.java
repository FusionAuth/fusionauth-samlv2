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
package org.inversoft.samlv2.domain;

/**
 * Enumeration for the SAML v2.0 status codes in the Response.
 *
 * @author Brian Pontarelli
 */
public enum ResponseStatus {
  /**
   * The responding provider was unable to successfully authenticate the principal.
   */
  AuthenticationFailed("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),

  /**
   * Unexpected or invalid content was encountered within a &lt;saml:Attribute> or &lt;saml:AttributeValue> element.
   */
  InvalidAttribute("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"),

  /**
   * The responding provider cannot or will not support the requested name identifier policy.
   */
  InvalidNameIDPolicy("urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"),

  /**
   * The specified authentication context requirements cannot be met by the responder.
   */
  NoAuthenticationContext("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"),

  /**
   * Used by an intermediary to indicate that none of the supported identity provider &lt;Loc> elements in an
   * &lt;IDPList> can be resolved or that none of the supported identity providers are available
   */
  NoAvailableIDP("urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"),

  /**
   * Indicates the responding provider cannot authenticate the principal passively, as has been requested.
   */
  NoPassive("urn:oasis:names:tc:SAML:2.0:status:NoPassive"),

  /**
   * Used by an intermediary to indicate that none of the identity providers in an &lt;IDPList> are supported by the
   * intermediary.
   */
  NoSupportedIDP("urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"),

  /**
   * Used by a session authority to indicate to a session participant that it was not able to propagate logout to all
   * other session participants.
   */
  PartialLogout("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"),

  /**
   * Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the
   * request further.
   */
  ProxyCountExceeded("urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"),

  /**
   * The request could not be performed due to an error on the part of the requester.
   */
  Requester("urn:oasis:names:tc:SAML:2.0:status:Requester"),

  /**
   * The SAML responder or SAML authority is able to process the request but has chosen not to respond. This status code
   * MAY be used when there is concern about the security context of the request message or the sequence of request
   * messages received from a particular requester.
   */
  RequestDenied("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),

  /**
   * The SAML responder or SAML authority does not support the request.
   */
  RequestUnsupported("urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"),

  /**
   * The SAML responder cannot process any requests with the protocol version specified in the request.
   */
  RequestVersionDeprecated("urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"),

  /**
   * The SAML responder cannot process the request because the protocol version specified in the request message is a
   * major upgrade from the highest protocol version supported by the responder.
   */
  RequestVersionTooHigh("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"),

  /**
   * The SAML responder cannot process the request because the protocol version specified in the request message is too
   * low.
   */
  RequestVersionTooLow("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"),

  /**
   * The resource value provided in the request message is invalid or unrecognized.
   */
  ResourceNotRecognized("urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"),

  /**
   * The request could not be performed due to an error on the part of the SAML responder or SAML authority.
   */
  Responder("urn:oasis:names:tc:SAML:2.0:status:Responder"),

  /**
   * The request succeeded. Additional information MAY be returned in the &lt;StatusMessage> and/or &lt;StatusDetail>
   * elements.
   */
  Success("urn:oasis:names:tc:SAML:2.0:status:Success"),

  /**
   * The response message would contain more elements than the SAML responder is able to return.
   */
  TooManyResponses("urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"),

  /**
   * An entity that has no knowledge of a particular attribute profile has been presented with an attribute drawn from
   * that profile.
   */
  UnknownAttributeProfile("urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"),

  /**
   * The responding provider does not recognize the principal specified or implied by the request.
   */
  UnknownPrincipal("urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"),

  /**
   * The SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
   */
  UnsupportedBinding("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"),

  /**
   * The SAML responder could not process the request because the version of the request message was incorrect.
   */
  VersionMismatch("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");

  /**
   * The SAML string.
   */
  private final String samlFormat;

  private ResponseStatus(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  /**
   * Locates the ResponseStatus using the given SAML String. This is the value from the StatusCode element's value.
   *
   * @param samlFormat The SAML string.
   * @return The ResponseStatus enum instance.
   * @throws IllegalArgumentException If the samlFormat String is not a valid status code.
   */
  public static ResponseStatus fromSAMLFormat(String samlFormat) {
    if (samlFormat == null) {
      return null;
    }

    for (ResponseStatus status : ResponseStatus.values()) {
      if (status.toSAMLFormat().equals(samlFormat)) {
        return status;
      }
    }

    throw new IllegalArgumentException("Invalid SAML v2.0 status value [" + samlFormat + "]");
  }

  public String toSAMLFormat() {
    return samlFormat;
  }
}
