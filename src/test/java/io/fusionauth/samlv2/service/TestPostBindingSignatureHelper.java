/*
 * Copyright (c) 2020, Inversoft Inc., All Rights Reserved
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

import io.fusionauth.samlv2.service.SAMLv2Service.PostBindingSignatureHelper;

/**
 * @author Daniel DeGroff
 */
public class TestPostBindingSignatureHelper implements PostBindingSignatureHelper {
  public KeySelector keySelector;

  public boolean verifySignature;

  public TestPostBindingSignatureHelper() {
  }

  public TestPostBindingSignatureHelper(KeySelector keySelector, boolean verifySignature) {
    this.keySelector = keySelector;
    this.verifySignature = verifySignature;
  }

  @Override
  public KeySelector keySelector() {
    return keySelector;
  }

  @Override
  public boolean verifySignature() {
    return verifySignature;
  }
}
