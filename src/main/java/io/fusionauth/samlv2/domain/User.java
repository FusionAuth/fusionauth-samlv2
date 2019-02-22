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
package io.fusionauth.samlv2.domain;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Models a single User within the system. This information is returned from the SAML IDP as NameID values.
 *
 * @author Brian Pontarelli
 */
public class User {
  public NameIDFormat format;

  public String id;

  public Map<String, Number> numberAttributes = new HashMap<String, Number>();

  public String qualifier;

  public String spProviderID;

  public String spQualifier;

  public Map<String, String> stringAttributes = new HashMap<String, String>();

  public Map<String, List<String>> stringListAttributes = new HashMap<String, List<String>>();

  public User(NameIDFormat format, String id, String qualifier, String spProviderID, String spQualifier) {
    this.format = format;
    this.id = id;
    this.qualifier = qualifier;
    this.spProviderID = spProviderID;
    this.spQualifier = spQualifier;
  }
}
