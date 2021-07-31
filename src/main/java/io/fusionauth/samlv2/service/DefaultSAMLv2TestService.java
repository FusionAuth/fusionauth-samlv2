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
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.LogoutRequestType;

/**
 * @author Daniel DeGroff
 */
@SuppressWarnings("unused")
public class DefaultSAMLv2TestService extends DefaultSAMLv2Service implements SAMLv2TestService {
  @Override
  public String buildInvalidTestingPostAuthnRequest(AuthenticationRequest request, boolean sign, PrivateKey privateKey,
                                                    X509Certificate certificate, Algorithm algorithm,
                                                    String xmlSignatureC14nMethod) throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, SamlTestVersion);
    return buildPostRequest(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, true);
  }

  @Override
  public String buildInvalidTestingPostLogoutRequest(LogoutRequest request, boolean sign, PrivateKey privateKey,
                                                     X509Certificate certificate, Algorithm algorithm,
                                                     String xmlSignatureC14nMethod) throws SAMLException {
    LogoutRequestType logoutRequest = toLogoutRequest(request, SamlTestVersion);
    return buildPostRequest(PROTOCOL_OBJECT_FACTORY.createLogoutRequest(logoutRequest), LogoutRequestType.class, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, true);
  }

  @Override
  public String buildInvalidTestingRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign,
                                                        PrivateKey key, Algorithm algorithm) throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, SamlTestVersion);
    return buildRedirectRequest(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class, relayState, sign, key, algorithm);
  }

  @Override
  public String buildInvalidTestingRedirectLogoutRequest(LogoutRequest request, String relayState, boolean sign,
                                                         PrivateKey key, Algorithm algorithm) throws SAMLException {
    LogoutRequestType logoutRequest = toLogoutRequest(request, SamlTestVersion);
    return buildRedirectRequest(PROTOCOL_OBJECT_FACTORY.createLogoutRequest(logoutRequest), LogoutRequestType.class, relayState, sign, key, algorithm);
  }
}
