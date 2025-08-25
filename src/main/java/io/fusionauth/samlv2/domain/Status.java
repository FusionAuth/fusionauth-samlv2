/*
 * Copyright (c) 2019-2025, Inversoft Inc., All Rights Reserved
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

import java.util.Objects;

/**
 * Status object.
 *
 * @author Brian Pontarelli
 */
public class Status {
  public ResponseStatus code;

  public String message;

  public Status() {
  }

  public Status(Status other) {
    this.code = other.code;
    this.message = other.message;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Status status = (Status) o;
    return code == status.code && Objects.equals(message, status.message);
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, message);
  }
}
