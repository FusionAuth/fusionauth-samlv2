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
package org.inversoft.samlv2.service;

import java.util.Set;

import org.inversoft.samlv2.domain.jaxb.oasis.protocol.ResponseType;

/**
 * This interface defines a mechanism where SAML v2.0 Response attributes are converted into Roles. Not all users of
 * the library will need this behavior, but it is defined in case you do. A no-op version is provided for anyone that
 * doesn't need Role resolution.
 *
 * @author Brian Pontarelli
 */
public interface RoleResolver {
  /**
   * Parses the roles from the given attribute statement.
   *
   * @param response The SAML response.
   * @return The roles.
   */
  Set<String> parseRoles(ResponseType response);
}
