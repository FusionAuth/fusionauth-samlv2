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

import javax.xml.crypto.KeySelector;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.function.Function;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.LogoutRequest;
import io.fusionauth.samlv2.domain.LogoutResponse;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.SignatureLocation;

/**
 * Service that can be used for the SAML v2.0 bindings to SAML core schemas and protocols.
 *
 * @author Brian Pontarelli
 */
public interface SAMLv2Service {
  /**
   * Builds a SAML AuthnResponse that can be sent back to the service provider.
   *
   * @param response               The authentication response that is converted to a AuthnResponse.
   * @param sign                   Determines if the XML should be signed or not.
   * @param privateKey             The key that is used to sign the response (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the response.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @param signatureLocation      The signature location that instructs where to place the signature in the response.
   * @param includeKeyInfo         When true the KeyInfo element will be added to the response
   * @return The response base-64 encoded.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildAuthnResponse(AuthenticationResponse response, boolean sign, PrivateKey privateKey,
                            X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod,
                            SignatureLocation signatureLocation, boolean includeKeyInfo)
      throws SAMLException;

  /**
   * Builds the metadata response for a SAML IdP.
   *
   * @param metaData The metadata to build XMl from.
   * @return The metadata response XML as a String.
   * @throws SAMLException If the JAXB marshalling failed.
   */
  String buildMetadataResponse(MetaData metaData) throws SAMLException;

  /**
   * Builds a HTTP-POST binding to a AuthnRequest protocol.
   *
   * @param request                The AuthnRequest information.
   * @param sign                   Determines if the request should be signed or not.
   * @param privateKey             The key that is used to sign the request (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the request.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @return The encoded value to be sent in the HTTP POST body.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildPostAuthnRequest(AuthenticationRequest request, boolean sign, PrivateKey privateKey,
                               X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException;

  /**
   * Build a Logout Request for an HTTP-POST binding for a session participant.
   *
   * @param logoutRequest          the logout request.
   * @param sign                   Determines if the request should be signed or not.
   * @param privateKey             The key that is used to sign the request (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the request.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @return The encoded value to be sent in the HTTP POST body.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildPostLogoutRequest(LogoutRequest logoutRequest, boolean sign, PrivateKey privateKey,
                                X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException;

  /**
   * Build a Logout Response for an HTTP-POST binding for an SP.
   *
   * @param logoutResponse         the logout response.
   * @param sign                   Determines if the response should be signed or not.
   * @param privateKey             The key that is used to sign the response (private key, shared, secret, etc).
   * @param certificate            The certificate that is included in the response.
   * @param algorithm              The signing algorithm to use (if any).
   * @param xmlSignatureC14nMethod The XML signature canonicalization method used.
   * @return The encoded value to be sent in the HTTP POST body.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildPostLogoutResponse(LogoutResponse logoutResponse, boolean sign, PrivateKey privateKey,
                                 X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException;

  /**
   * Builds a HTTP-Redirect binding to a AuthnRequest protocol.
   *
   * @param request    The AuthnRequest information.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign, PrivateKey key,
                                   Algorithm algorithm) throws SAMLException;

  /**
   * Build a Logout Request for HTTP Redirect bindings.
   *
   * @param request    the Logout request information.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildRedirectLogoutRequest(LogoutRequest request, String relayState, boolean sign, PrivateKey key,
                                    Algorithm algorithm)
      throws SAMLException;

  /**
   * Build a Logout Response for HTTP Redirect bindings.
   *
   * @param response   the Logout response information.
   * @param relayState The relay state parameter (required if signing).
   * @param sign       Determines if the request should be signed or not.
   * @param key        The key that is used to sign the request (private key, shared, secret, etc).
   * @param algorithm  The signing algorithm to use (if any).
   * @return The URL parameters that can be appended to a redirect URL. This does not include the question mark.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  String buildRedirectLogoutResponse(LogoutResponse response, String relayState, boolean sign, PrivateKey key,
                                     Algorithm algorithm) throws SAMLException;

  /**
   * Parses the logout request from an HTTP POST binding and verifies that the signature is valid.
   *
   * @param encodedRequest  the encoded SAML request from an HTTP POST binding.
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The parsed request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  LogoutRequest parseLogoutRequestPostBinding(String encodedRequest,
                                              Function<LogoutRequest, PostBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses a HTTP-Redirect binding to a Logout request.
   *
   * @param encodedRequest  the encoded SAML request, the request will be assumed to be encoded an deflated.
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The parsed request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  LogoutRequest parseLogoutRequestRedirectBinding(String encodedRequest, String relayState,
                                                  Function<LogoutRequest, RedirectBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses the logout response from an HTTP POST binding and verifies that the signature is valid.
   *
   * @param encodedRequest  the encoded SAML request from an HTTP POST binding.
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The parsed request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  LogoutResponse parseLogoutResponsePostBinding(String encodedRequest,
                                                Function<LogoutResponse, PostBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses a HTTP-Redirect binding to a Logout response.
   *
   * @param encodedRequest  the encoded SAML request, the request will be assumed to be encoded an deflated.
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The parsed request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  LogoutResponse parseLogoutResponseRedirectBinding(String encodedRequest, String relayState,
                                                    Function<LogoutResponse, RedirectBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses a SAML 2.0 MetaData response and converts it to a simple to use object.
   *
   * @param metaDataXML The MetaData XML.
   * @return The MetaData object.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  MetaData parseMetaData(String metaDataXML) throws SAMLException;

  /**
   * Parses the authentication request from an HTTP POST binding and verifies that it is valid.
   *
   * @param encodedRequest  The encoded SAML request from an HTTP POST binding.
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The parsed request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationRequest parseRequestPostBinding(String encodedRequest,
                                                Function<AuthenticationRequest, PostBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses the authentication request from an HTTP redirect binding and verifies that it is valid.
   *
   * @param encodedRequest  The encoded SAML request, the request will be assumed to be encoded an deflated.
   * @param relayState      The RelayState URL parameter (only needed if verifying signatures).
   * @param signatureHelper the signature helper used to determine if a signature is required and to provide additional
   *                        necessary details to complete signature verification.
   * @return The request.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationRequest parseRequestRedirectBinding(String encodedRequest, String relayState,
                                                    Function<AuthenticationRequest, RedirectBindingSignatureHelper> signatureHelper)
      throws SAMLException;

  /**
   * Parses the authentication response from the given String and verifies that it is valid.
   *
   * @param response        The response in base 64 deflated format.
   * @param verifySignature Determines if the responses signature should be verified or not.
   * @param keySelector     The key selector that is used to find the correct key to verify the signature in the
   *                        response.
   * @return The response.
   * @throws SAMLException If any unrecoverable errors occur.
   */
  AuthenticationResponse parseResponse(String response, boolean verifySignature, KeySelector keySelector)
      throws SAMLException;


  interface PostBindingSignatureHelper {
    /**
     * @return the key selector to be used to find the correct key to verify the signature.
     */
    KeySelector keySelector();

    /**
     * @return true if the signature should be verified.
     */
    boolean verifySignature();
  }

  interface RedirectBindingSignatureHelper {
    /**
     * @return the algorithm used to verify the signature.
     */
    Algorithm algorithm();

    /**
     * @return the public key used to verify the signature.
     */
    PublicKey publicKey();

    /**
     * @return the signature string from the HTTP request to verify.
     */
    String signature();

    /**
     * @return true if the signature should be verified.
     */
    boolean verifySignature();
  }
}
