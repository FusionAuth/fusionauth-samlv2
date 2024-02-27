/*
 * Copyright (c) 2021-2022, Inversoft Inc., All Rights Reserved
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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.util.SAMLRequestParameters;
import io.fusionauth.samlv2.util.SAMLTools;
import org.testng.annotations.Test;
import static org.testng.Assert.assertNull;

/**
 * @author Daniel DeGroff
 */
public class SAMLToolsTest {
  @Test
  public void parseQueryString() {
    // Account for null
    SAMLRequestParameters actual = SAMLTools.parseQueryString(null);

    assertNull(actual.RelayState);
    assertNull(actual.SAMLRequest);
    assertNull(actual.SigAlg);
    assertNull(actual.Signature);

    assertNull(actual.urlDecodedRelayState());
    assertNull(actual.urlDecodedSAMLRequest());
    assertNull(actual.urlDecodedSigAlg());
    assertNull(actual.urlDecodedSignature());
  }

  @Test
  public void truncatedRequest() throws SAMLException {
    // Ensure we can handle a truncated deflated AuthN request.
    // - As long as this test doesn't hang we are good.
    String truncated = "fVPBjpswEL1X6j8g7gHDJqFYSSqaqGqkbRcF2kMvlWsPjSVsU3vYTf++hk22qbSEC5L95s2b9zwrx1Tb0aLHoz7A7x4cBifVakfHi3XYW00Nc9JRzRQ4ipxWxed7mkaEdtag4aYN374JXvn+8dymYc6BRWn0BM9+tw5/vCN5RrKGkDvCFoKQZUp4LnLR5FmzTDPWQC44T+cTHN/AOt9hHfqGE5DSmkcpwH7xAtdhVQbozZiS5FwPe+2QafScJJnPSDZLlnV6RxcpnS++TxTuPKfUDEctR8SOxrEUXQQnproWIm5UXFUPFdhHySHqjt202tH7D1ILqX/ddvjnM8jRT3VdzsqHqp5gLS5RbI12vQJ7FvL1cP8i1/2vVoAySewbwGmQ+55xF24G9tWQPB2dsptbtQqQCYZsKF/F11UvNB0dUtnvStNK/if4aKxiOD1zEiXjiRSzZoRSUEy2hRAWnAuDom3N09YCQ5802h7C+LrXeRFAjGvhrUA4YbA1qmNWuiE5PwTH5zEvg15jt61/";
    SAMLTools.decodeAndInflate(truncated);
  }

  @Test
  public void invalidEndingRequest() throws SAMLException {
    // Ensure we can handle a request with an invalid ending
    // - As long as this test doesn't hang we are good.
    String invalidEnding = "rVPLjtMwFN33K0bZp3acNA+rrVSmPCqVtpoWFmzQjX0zY8mxg+0M8PekCTADErPiLo/vedwjeemh1R3f9OHB3OGXHn2Y3QzzrdXG8/FxFfXOcAteeW6gRc+D4OfN+z1nc8o7Z4MVVkd/0V5mgffogrJmou22q+h4eL0/vt0dPlMJ0FSAkiKrMlo1Iq/qTLCyElglNSSsyOsG0on6EZ0fdFbRIBvNJjXve9wZH8CEAacsiymLaXahlC9STumnibodjlUGwkh/CKHznBAQwvYm+LkGI91c2JZcz3lkRNt7ZUhVDP5CprEYEsVZI2gMktK4TvK8grTEMl9M8qefzbxSRipz/3Ih9bTk+bvL5RSfjufLJLL5VdStNb5v0Z3RPSqBH+72T5k1gjPPAoNsh6TQqTE6yVNR1qVIMppDg01RUpGyWiBJ8rLIskVa0oKxhPhu3GcxCB+tR/vlFeBjoW79/+1aDCAhwJI893ly7vhhaGq3PVmtxPcRv84b61oI/y40mScjomTcjKscW1B6I6VD76PfOhut7ddbhxBwFQXXY3RD1rMpzJ9/Yv0D,'\"QnoVale";
    SAMLTools.decodeAndInflate(invalidEnding);
  }
}
