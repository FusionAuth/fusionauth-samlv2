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

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

/**
 * This class models a SAML v2.0 authentication request from a SP to an IDP.
 *
 * @author Brian Pontarelli
 */
public class AuthenticationRequest {
  public String id;
  public String encodedRequest;
  public byte[] rawResult;

  public AuthenticationRequest(String id, String encodedRequest, byte[] rawResult) {
    this.id = id;
    this.encodedRequest = encodedRequest;
    this.rawResult = rawResult;
  }

  public URL toRedirectURL(URL baseURL) {
    String urlString = baseURL.toString();
    try {
      String encodedParameter = URLEncoder.encode(encodedRequest, "UTF-8");
      urlString = urlString.contains("?") ? urlString + "&SAMLRequest=" + encodedParameter : urlString + "?SAMLRequest=" + encodedParameter;
      return new URL(urlString);
    } catch (MalformedURLException e) {
      throw new RuntimeException("Unable to build SAML v2.0 redirect URL", e);
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("Unable to build SAML v2.0 redirect URL", e);
    }
  }
}
