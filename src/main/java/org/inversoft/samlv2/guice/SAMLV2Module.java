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
package org.inversoft.samlv2.guice;

import org.inversoft.samlv2.service.AuthenticationService;
import org.inversoft.samlv2.service.DefaultAuthenticationService;

import com.google.inject.AbstractModule;

/**
 * A Guice module that binds all of the SAML v2.0 classes.
 *
 * @author Brian Pontarelli
 */
public abstract class SAMLV2Module extends AbstractModule {
  @Override
  protected void configure() {
    bind(AuthenticationService.class).to(DefaultAuthenticationService.class);
    bindRoleResolver();
  }

  /**
   * Binds the RoleResolver interface.
   */
  protected abstract void bindRoleResolver();
}
