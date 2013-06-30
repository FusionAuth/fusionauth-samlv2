package org.inversoft.samlv2.service;

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.AuthenticationResponse;
import org.inversoft.samlv2.domain.NameIDFormat;

/**
 * Service that can be used for building SAML v2.0 authentication requests.
 *
 * @author Brian Pontarelli
 */
public interface AuthenticationRequestService {
  /**
   * Builds a SAML v2.0 authentication request.
   *
   * @param issuer The issuer that is put into the SAML request.
   * @param format The NameIDPolicy format.
   * @return The request.
   */
  AuthenticationRequest buildRequest(String issuer, NameIDFormat format);

  /**
   * Parses the authentication response from the given String and verifies that it is valid.
   *
   * @param response The response in base 64 deflated format.
   * @return The response.
   */
  AuthenticationResponse parseResponse(String response);
}
