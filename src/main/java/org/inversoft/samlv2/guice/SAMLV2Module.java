package org.inversoft.samlv2.guice;

import org.inversoft.samlv2.service.AuthenticationService;
import org.inversoft.samlv2.service.DefaultAuthenticationService;

import com.google.inject.AbstractModule;

/**
 * A Guice module that binds all of the SAML v2.0 classes.
 *
 * @author Brian Pontarelli
 */
public class SAMLV2Module extends AbstractModule {
  @Override
  protected void configure() {
    bind(AuthenticationService.class).to(DefaultAuthenticationService.class);
  }
}
