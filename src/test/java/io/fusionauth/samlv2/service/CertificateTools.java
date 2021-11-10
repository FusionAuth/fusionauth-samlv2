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
package io.fusionauth.samlv2.service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;

import io.fusionauth.samlv2.domain.Algorithm;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

@SuppressWarnings("WeakerAccess")
public class CertificateTools {
  /**
   * Converts a key pair to a certificate.
   *
   * @param keyPair   The key pair.
   * @param algorithm The algorithm of the certificates.
   * @param issuer    The name of the issuer of the certificate.
   * @return The Certificate.
   * @throws IllegalArgumentException If the input is not valid and the certificate could not be created.
   */
  public static X509Certificate fromKeyPair(KeyPair keyPair, Algorithm algorithm, String issuer)
      throws IllegalArgumentException {
    try {
      X509CertInfo certInfo = new X509CertInfo();
      CertificateX509Key certKey = new CertificateX509Key(keyPair.getPublic());
      certInfo.set(X509CertInfo.KEY, certKey);
      certInfo.set(X509CertInfo.VERSION, new CertificateVersion(1));
      certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(new AlgorithmId(ObjectIdentifier.of(KnownOIDs.SHA256withRSA))));
      certInfo.set(X509CertInfo.ISSUER, new X500Name("cn=" + issuer));
      certInfo.set(X509CertInfo.SUBJECT, new X500Name("cn=" + issuer));
      certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(new Date(0), new Date(ZonedDateTime.now().plusYears(99).toInstant().toEpochMilli())));
      certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(BigInteger.valueOf(System.currentTimeMillis())));

      X509CertImpl impl = new X509CertImpl(certInfo);
      impl.sign(keyPair.getPrivate(), algorithm.name);
      return impl;
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }
}
