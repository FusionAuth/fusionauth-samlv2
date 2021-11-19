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
package io.fusionauth.samlv2.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * A POJO to hold raw query parameters that have not been URL decoded.
 *
 * @author Daniel DeGroff
 */
public class SAMLRequestParameters {

  public String RelayState;

  public String SAMLRequest;

  public String SigAlg;

  public String Signature;

  public String urlDecodedRelayState() {
    return urlDecode(RelayState);
  }

  public String urlDecodedSAMLRequest() {
    return urlDecode(SAMLRequest);
  }

  public String urlDecodedSigAlg() {
    return urlDecode(SigAlg);
  }

  public String urlDecodedSignature() {
    return urlDecode(Signature);
  }

  private String urlDecode(String s) {
    if (s == null) {
      return null;
    }

    return URLDecoder.decode(s, StandardCharsets.UTF_8);
  }
}
