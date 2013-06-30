package org.inversoft.samlv2.domain;

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
}
