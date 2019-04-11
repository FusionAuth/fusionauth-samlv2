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

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.SAMLException;

/**
 * Service that can be used for the SAML v2.0 bindings to SAML core schemas and protocols.
 *
 * @author Brian Pontarelli
 */
public interface SAMLv2Service {
  /**
   * Builds a SAML AuthnResponse that can be sent back to the service provider.
   *
   * @param response   The authentication response that is converted to a AuthnResponse.
   * @param sign       Determines if the XML should be signed or not.
   * @param publicKey  The public key to include in the XML signature.
   * @param privateKey The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The response base-64 encoded.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildAuthnResponse(AuthenticationResponse response, boolean sign, PublicKey publicKey, PrivateKey privateKey,
                            Algorithm algorithm) throws SAMLException;

  /**
   * Builds a HTTP-Redirect binding to a AuthnRequest protocol.
   *
   * @param id         The request id that is echoed in the response.
   * @param issuer     The issuer that is put into the SAML request.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign, PrivateKey key,
                                       Algorithm algorithm) throws SAMLException;

  /**
   * Builds the metadata response for a SAML IdP.
   *
   * @param metaData The metadata to build XMl from.
   * @return The metadata response XML as a String.
   * @throws SAMLException If the JAXB marshalling failed.
   */
  String buildMetadataResponse(MetaData metaData) throws SAMLException;

  /**
   * Builds an invalid HTTP-Redirect binding to a AuthnRequest protocol for testing.
   *
   * @param id         The request id that is echoed in the response.
   * @param issuer     The issuer that is put into the SAML request.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildInvalidTestingHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign,
                                                     PrivateKey key, Algorithm algorithm) throws SAMLException;

  /**
   * Parses a SAML 2.0 MetaData response and converts it to a simple to use object.
   *
   * @param metaDataXML The MetaData XML.
   * @return The MetaData object.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  MetaData parseMetaData(String metaDataXML) throws SAMLException;

  /**
   * Parses the authentication request from the given String and verifies that it is valid.
   *
   * @param encodedRequest  The encoded (and deflated) request from the URL parameter.
   * @param relayState      The RelayState URL parameter (only needed if verifying signatures).
   * @param signature       (Optional) The signature to validate.
   * @param verifySignature True if the signature should be verified.
   * @param key             (Optional) The key (signing certificate) used to verify the signature.
   * @param algorithm       (Optional) The key algorithm used to verify the signature.
   * @return The request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationRequest parseRequest(String encodedRequest, String relayState, String signature,
                                     boolean verifySignature, PublicKey key, Algorithm algorithm) throws SAMLException;

  /**
   * Parses the authentication response from the given String and verifies that it is valid.
   *
   * @param response        The response in base 64 deflated format.
   * @param verifySignature Determines if the responses signature should be verified or not.
   * @param key             The key (signing certificate) used to verify the signature in the response.
   * @return The response.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationResponse parseResponse(String response, boolean verifySignature, PublicKey key) throws SAMLException;
}
