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

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.PublicKey;

/**
 * @author Daniel DeGroff
 */
public class TestKeySelector extends KeySelector {
  private final PublicKey defaultKey;

  public TestKeySelector(PublicKey defaultKey) {
    this.defaultKey = defaultKey;
  }

  @Override
  public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) {
    // keyInfo may be null
    if (keyInfo == null) {
      return () -> defaultKey;
    }


    // Attempt to read the keyInfo as we would IRL, so we will NPE in theory. This ensures we can handle a response with keyInfo.
    keyInfo.getContent().stream().filter(xml -> xml instanceof X509Data).findFirst().orElse(null);
    return () -> defaultKey;
  }
}

