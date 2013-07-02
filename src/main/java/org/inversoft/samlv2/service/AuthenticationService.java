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
package org.inversoft.samlv2.service;

import java.security.Key;
import java.security.KeyPair;

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.AuthenticationResponse;
import org.inversoft.samlv2.domain.NameIDFormat;

/**
 * Service that can be used for building SAML v2.0 authentication requests.
 *
 * @author Brian Pontarelli
 */
public interface AuthenticationService {
  /**
   * Builds a SAML v2.0 authentication request.
   *
   * @param issuer  The issuer that is put into the SAML request.
   * @param format  The NameIDPolicy format.
   * @param sign    Determines if the request should be signed or not.
   * @param keyPair The key pair used to sign the request. This cannot be null if the sign flag is true.
   * @return The request.
   */
  AuthenticationRequest buildRequest(String issuer, NameIDFormat format, boolean sign, KeyPair keyPair);

  /**
   * Parses the authentication response from the given String and verifies that it is valid.
   *
   * @param response        The response in base 64 deflated format.
   * @param verifySignature Determines if the responses signature should be verified or not.
   * @param key             The public key (signing certificate) used to verify the signature in the response.
   * @return The response.
   */
  AuthenticationResponse parseResponse(String response, boolean verifySignature, Key key);
}
