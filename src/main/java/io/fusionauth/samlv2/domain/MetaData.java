/*
 * Copyright (c) 2019, Inversoft Inc., All Rights Reserved
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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class MetaData {
  public String entityId;

  public String id;

  public IDPMetaData idp;

  public SPMetaData sp;

  public static class IDPMetaData {
    public List<Certificate> certificates = new ArrayList<>();

    public List<String> postBindingLogoutEndpoints = new ArrayList<>();

    public List<String> postBindingSignInEndpoints = new ArrayList<>();

    public List<String> redirectBindingLogoutEndpoints = new ArrayList<>();

    public List<String> redirectBindingSignInEndpoints = new ArrayList<>();

    public boolean wantAuthnRequestsSigned;
  }

  public static class SPMetaData {
    public String acsEndpoint;

    public boolean authnRequestsSigned;

    public List<Certificate> certificates = new ArrayList<>();

    public NameIDFormat nameIDFormat;

    public boolean wantAssertionsSigned;
  }
}
