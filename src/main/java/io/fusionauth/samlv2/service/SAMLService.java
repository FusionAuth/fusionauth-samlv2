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
package io.fusionauth.samlv2.service;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.SAMLException;

/**
 * Service that can be used for the SAML v2.0 bindings to SAML core schemas and protocols.
 *
 * @author Brian Pontarelli
 */
public interface SAMLService {
  /**
   * Builds a HTTP-Redirect binding to a AuthnRequest protocol.
   *
   * @param id         The request id that is echoed in the response.
   * @param issuer     The issuer that is put into the SAML request.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The private key that is used to sign the request.
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign, PrivateKey key)
      throws SAMLException;

  /**
   * Parses the authentication response from the given String and verifies that it is valid.
   *
   * @param response        The response in base 64 deflated format.
   * @param verifySignature Determines if the responses signature should be verified or not.
   * @param key             The public key (signing certificate) used to verify the signature in the response.
   * @return The response.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationResponse parseResponse(String response, boolean verifySignature, PublicKey key) throws SAMLException;
}
