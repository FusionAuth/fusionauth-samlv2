/*
 * Copyright (c) 2021, Inversoft Inc., All Rights Reserved
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
import java.security.cert.X509Certificate;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.LogoutRequest;
import io.fusionauth.samlv2.domain.SAMLException;

/**
 * Service that can be used for building invalid requests to test the SAML v2.0 bindings to SAML core schemas and
 * protocols.
 *
 * @author Daniel DeGroff
 */
public interface SAMLv2TestService {
  String SamlTestVersion = "bad";

  /**
   * Builds an invalid POST binding to a AuthnRequest protocol for testing.
   *
   * @param request                The AuthnRequest information.
   * @param sign                   Determines if the request should be signed or not.
   * @param privateKey             The key that is used to sign the request (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the request.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  @SuppressWarnings("unused")
  String buildInvalidTestingPostAuthnRequest(AuthenticationRequest request, boolean sign, PrivateKey privateKey,
                                             X509Certificate certificate, Algorithm algorithm,
                                             String xmlSignatureC14nMethod) throws SAMLException;

  /**
   * Builds an invalid POST binding to a LogoutRequest for testing.
   *
   * @param request                The LogoutRequest information.
   * @param sign                   Determines if the request should be signed or not.
   * @param privateKey             The key that is used to sign the request (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the request.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  @SuppressWarnings("unused")
  String buildInvalidTestingPostLogoutRequest(LogoutRequest request, boolean sign, PrivateKey privateKey,
                                              X509Certificate certificate, Algorithm algorithm,
                                              String xmlSignatureC14nMethod) throws SAMLException;

  /**
   * Builds an invalid HTTP-Redirect binding to a AuthnRequest protocol for testing.
   *
   * @param request    The AuthnRequest information.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param privateKey The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  @SuppressWarnings("unused")
  String buildInvalidTestingRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign,
                                                 PrivateKey privateKey, Algorithm algorithm) throws SAMLException;

  /**
   * Builds an invalid Redirect binding to a Logout Request for testing.
   *
   * @param request    The LogoutRequest information.
   * @param sign       Determines if the request should be signed or not.
   * @param privateKey The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  @SuppressWarnings("unused")
  String buildInvalidTestingRedirectLogoutRequest(LogoutRequest request, String relayState, boolean sign,
                                                  PrivateKey privateKey, Algorithm algorithm) throws SAMLException;
}
