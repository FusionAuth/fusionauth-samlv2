/*
 * Copyright (c) 2021-2023, Inversoft Inc., All Rights Reserved
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
package io.fusionauth.samlv2.util;

import javax.xml.XMLConstants;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import io.fusionauth.samlv2.domain.NameID;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.NameIDType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.KeyDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.X509DataType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;
import static javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING;

/**
 * @author Daniel DeGroff
 */
@SuppressWarnings("unused")
public class SAMLTools {
  private static final Map<String, Boolean> FactoryFeatures = new HashMap<>();

  private static final Map<Class<?>, Unmarshaller> UnmarshallerCache = new ConcurrentHashMap<>();

  private static final Logger logger = LoggerFactory.getLogger(SAMLTools.class);

  static {
    FactoryFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", true);
    FactoryFeatures.put("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    FactoryFeatures.put("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
    FactoryFeatures.put("http://xml.org/sax/features/external-general-entities", false);
    FactoryFeatures.put("http://xml.org/sax/features/external-parameter-entities", false);
  }

  /**
   * Convert an attribute to a string.
   *
   * @param attribute the attribute in object form
   * @return a string version of the attribute.
   */
  public static String attributeToString(Object attribute) {
    if (attribute == null) {
      return null;
    }

    if (attribute instanceof Number) {
      return attribute.toString();
    } else if (attribute instanceof String) {
      return (String) attribute;
    } else if (attribute instanceof Element) {
      return ((Element) attribute).getTextContent();
    } else {
      logger.warn("This library currently doesn't handle attributes of type [" + attribute.getClass() + "]");
    }

    return null;
  }

  /**
   * Convert a calendar object of type <code>XMLGregorianCalendar</code> to a ZonedDateTime.
   *
   * @param cal a calendar object
   * @return a zoned date time object
   */
  public static ZonedDateTime convertToZonedDateTime(XMLGregorianCalendar cal) {
    return cal != null ? cal.toGregorianCalendar().toZonedDateTime() : null;
  }

  /**
   * Decode the encoded request or response.
   *
   * @param base64Encoded the encoded request or response
   * @return a decoded and request as bytes
   */
  public static byte[] decode(String base64Encoded) {
    return Base64.getMimeDecoder().decode(base64Encoded);
  }

  /**
   * Decode and inflate the encoded request.
   *
   * @param encodedRequest the encoded request
   * @return a decoded and inflated request as bytes
   * @throws SAMLException if $%#! goes south
   */
  public static byte[] decodeAndInflate(String encodedRequest) throws SAMLException {
    byte[] bytes = Base64.getMimeDecoder().decode(encodedRequest);
    Inflater inflater = new Inflater(true);
    inflater.setInput(bytes);

    try {
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      while (inflater.getRemaining() > 0) {
        int length = inflater.inflate(buf);
        if (length > 0) {
          os.write(buf, 0, length);
        } else {
          break;
        }
      }

      return os.toByteArray();
    } catch (DataFormatException e) {
      throw new SAMLException("Invalid AuthnRequest. Inflating the bytes failed.", e);
    }
  }

  /**
   * Decode the encoded request or response to a String.
   *
   * @param base64Encoded the encoded request or response
   * @return a decoded and request as a string
   */
  public static String decodeToString(String base64Encoded) {
    return new String(Base64.getMimeDecoder().decode(base64Encoded), StandardCharsets.UTF_8);
  }

  /**
   * Deflate and encode the provided byte array.
   *
   * @param bytes the byte array to deflate and encode.
   * @return an encoded string
   */
  public static String deflateAndEncode(byte[] bytes) {
    Deflater deflater = new Deflater(Deflater.DEFLATED, true);
    deflater.setInput(bytes);
    deflater.finish();
    byte[] deflatedResult = new byte[bytes.length];
    int length = deflater.deflate(deflatedResult);
    deflater.end();
    byte[] src = Arrays.copyOf(deflatedResult, length);
    return new String(Base64.getEncoder().encode(src), StandardCharsets.UTF_8);
  }

  /**
   * Encode the provided byte array.
   *
   * @param bytes the byte array to encode.
   * @return an encoded string
   */
  public static String encode(byte[] bytes) {
    return new String(Base64.getEncoder().encode(bytes), StandardCharsets.UTF_8);
  }

  /**
   * Serialize the JAXBElement to a byte array.
   *
   * @param object the JAXB element.
   * @param type   the class of the element.
   * @param <T>    the type of the element.
   * @return a byte array
   * @throws SAMLException if $%#! goes south.
   */
  public static <T> byte[] marshallToBytes(JAXBElement<T> object, Class<T> type) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Marshaller marshaller = context.createMarshaller();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      marshaller.marshal(object, os);
      return os.toByteArray();
    } catch (JAXBException e) {
      throw new SAMLException("Unable to marshallRequest JAXB SAML object to bytes.", e);
    }
  }

  /**
   * Marshall the JAXB element to a Document.
   *
   * @param object the JAXB element.
   * @param type   the class of the element.
   * @param <T>    the type of the element.
   * @return a document
   * @throws SAMLException if $%#! goes south
   */
  public static <T> Document marshallToDocument(JAXBElement<T> object, Class<T> type) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Marshaller marshaller = context.createMarshaller();
      Document document = newDocumentBuilder().newDocument();
      marshaller.marshal(object, document);

      return document;
    } catch (JAXBException | SAMLException e) {
      throw new SAMLException("Unable to marshallRequest JAXB SAML object to DOM.", e);
    }
  }

  /**
   * Serialize the provided document.
   *
   * @param document the document to serialize.
   * @return a string form of the serialized document.
   */
  public static String marshallToString(Document document) throws TransformerException {
    return marshallNodeToString(document, false);
  }

  /**
   * Serialize the provided element.
   *
   * @param element the element to serialize.
   * @return a string form of the serialized element.
   */
  public static String marshallToString(Element element) throws TransformerException {
    return marshallNodeToString(element, true);
  }

  /**
   * Return a new document builder
   *
   * @return a document builder
   * @throws SAMLException if $%#! goes south
   */
  public static DocumentBuilder newDocumentBuilder() throws SAMLException {
    // https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
    // https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#SAXTransformerFactory
    // https://web-in-security.blogspot.com/2014/11/detecting-and-exploiting-xxe-in-saml.html

    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);

      // Do not expand entity references
      dbf.setExpandEntityReferences(false);

      // Set default features
      for (String key : FactoryFeatures.keySet()) {
        try {
          dbf.setFeature(key, FactoryFeatures.get(key));
        } catch (IllegalArgumentException e) {
          // The parser may not recognize this attribute.
          logger.debug("Failed to set feature [" + key + "=" + FactoryFeatures.get(key) + "]. This may be expected if the parser does not recognize this feature.", e);
        }
      }

      // Enabling 'secure processing' disables loading of external DTD and external Schema.
      // - See constructor body on line 177 of DocumentBuilderImpl.
      dbf.setFeature(FEATURE_SECURE_PROCESSING, true);

      return dbf.newDocumentBuilder();
    } catch (ParserConfigurationException e) {
      throw new SAMLException("Unable to configure the DocumentBuilderFactory with feature [" + FEATURE_SECURE_PROCESSING + "].", e);
    }
  }

  /**
   * Parse the provided bytes into a document.
   *
   * @param bytes the bytes
   * @return a document
   * @throws SAMLException if $%#! goes south
   */
  public static Document newDocumentFromBytes(byte[] bytes) throws SAMLException {
    try {
      return newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
    } catch (SAXException | IOException e) {
      throw new SAMLException("Unable to parse SAML v2.0 document.", e);
    }
  }

  /**
   * Parse a NameIdType element and return a NameID enum.
   *
   * @param element the nameId element
   * @return a nameId enum value
   */
  public static NameID parseNameId(NameIDType element) {
    NameID nameId = new NameID();
    nameId.format = element.getFormat();
    nameId.id = element.getValue();
    return nameId;
  }

  /**
   * Separate query parameters, do not URL decode anything.
   *
   * @param queryString the query string to parse
   * @return a POJO containing non-URL decoded SAML query parameters.
   */
  public static SAMLRequestParameters parseQueryString(String queryString) {
    SAMLRequestParameters result = new SAMLRequestParameters();

    if (queryString == null) {
      return result;
    }

    String[] parts = queryString.split("&");
    for (String part : parts) {
      String[] param = part.split("=");
      if (param.length == 2) {
        switch (param[0]) {
          case "RelayState" -> result.RelayState = param[1];
          case "SAMLRequest" -> result.SAMLRequest = param[1];
          case "SigAlg" -> result.SigAlg = param[1];
          case "Signature" -> result.Signature = param[1];
        }
      }
    }

    return result;
  }

  /**
   * Convert a key descriptor type to a certificate
   *
   * @param keyDescriptorType the key descriptor type
   * @return a certificate or null if it could not be converted.
   */
  public static Certificate toCertificate(KeyDescriptorType keyDescriptorType) {
    try {
      List<Object> keyData = keyDescriptorType.getKeyInfo().getContent();
      for (Object keyDatum : keyData) {
        if (keyDatum instanceof JAXBElement<?> element) {
          if (element.getDeclaredType() == X509DataType.class) {
            X509DataType cert = (X509DataType) element.getValue();
            List<Object> certData = cert.getX509IssuerSerialOrX509SKIOrX509SubjectName();
            for (Object certDatum : certData) {
              element = (JAXBElement<?>) certDatum;
              if (element.getName().getLocalPart().equals("X509Certificate")) {
                byte[] certBytes = (byte[]) element.getValue();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return cf.generateCertificate(new ByteArrayInputStream(certBytes));
              }
            }
          }
        }
      }

      return null;
    } catch (CertificateException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Convert a ZonedDateTime instant to an XMlGregorianCalendar object.
   *
   * @param instant the instant
   * @return a calendar object.
   */
  public static XMLGregorianCalendar toXMLGregorianCalendar(ZonedDateTime instant) throws SAMLException {
    if (instant == null) {
      return null;
    }

    try {
      return DatatypeFactory.newInstance().newXMLGregorianCalendar(GregorianCalendar.from(instant));
    } catch (DatatypeConfigurationException e) {
      throw new SAMLException("Unable to initiate DataTypeFactor.", e);
    }
  }

  /**
   * Convert an XMLGregorianCalendar instant to a ZoneDateTime instant
   *
   * @param instant the instant
   * @return a ZoneDateTime object
   */
  public static ZonedDateTime toZonedDateTime(XMLGregorianCalendar instant) {
    if (instant == null) {
      return null;
    }

    return instant.toGregorianCalendar().toZonedDateTime();
  }

  /**
   * Convert a document to a JAXB Element.
   *
   * @param document the XML document
   * @param type     the class of the JAXB element to marshal the document to
   * @param <T>      the type
   * @return an object of type T
   * @throws SAMLException if $%#! goes south
   */
  public static <T> T unmarshallFromDocument(Document document, Class<T> type) throws SAMLException {
    try {
      Unmarshaller unmarshaller = getUnmarshaller(type);
      JAXBElement<T> element = unmarshaller.unmarshal(document, type);
      return element.getValue();
    } catch (JAXBException e) {
      throw new SAMLException("Unable to unmarshall SAML response", e);
    }
  }

  /**
   * Validate the document.
   *
   * @param document  the document
   * @param schemaURI the schema URI
   * @param errors    the errors object used to collect all errors from the validator.
   * @return true if the validation was successful, false otherwise.
   * @throws SAMLException if $%#! goes south
   */
  public static boolean validate(Document document, URL schemaURI, SchemaValidationErrors errors) throws SAMLException {
    Schema schema;
    try {
      SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      schemaFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      schema = schemaFactory.newSchema(schemaURI);
    } catch (SAXException e) {
      throw new SAMLException("An invalid schema was requested. Schema [" + schemaURI + "].", e);
    }

    Validator validator = schema.newValidator();
    validator.setErrorHandler(errors);

    // Disable external DTD while validating.
    try {
      validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    } catch (SAXNotRecognizedException | SAXNotSupportedException ignore) {
      // Not supported by the parser
    }

    // Disable external Schema while validating.
    try {
      validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    } catch (SAXNotRecognizedException | SAXNotSupportedException ignore) {
      // Not supported by the parser
    }

    Source source = new DOMSource(document);
    try {
      validator.validate(source);
    } catch (IOException | SAXException e) {
      throw new SAMLException("Failed to validate the document source.", e);
    }

    return errors.error.isEmpty() && errors.fatal.isEmpty() && errors.warning.isEmpty();
  }

  /**
   * Retrieve a JAXB unmarshaller for the specified type. Building the JAXBContext is rather slow, this method will
   * cache the result and will lazily build new contexts.
   *
   * @param type the type to be un-marshalled
   * @param <T>  the type
   * @return an unmarshaller
   * @throws SAMLException if $%#! goes south
   */
  private static <T> Unmarshaller getUnmarshaller(Class<T> type) throws SAMLException {
    Unmarshaller result = UnmarshallerCache.get(type);
    if (result == null) {
      try {
        JAXBContext context = JAXBContext.newInstance(type);
        result = context.createUnmarshaller();
      } catch (Exception e) {
        throw new SAMLException(e.getCause());
      }

      UnmarshallerCache.put(type, result);
    }

    return result;
  }

  /**
   * Serialize the provided node.
   *
   * @param node               the node to serialize.
   * @param omitXMLDeclaration If {@code true}, the XML declaration will be omitted from the string
   * @return a string form of the serialized node.
   */
  private static String marshallNodeToString(Node node, boolean omitXMLDeclaration) throws TransformerException {
    StringWriter sw = new StringWriter();
    TransformerFactory tf = TransformerFactory.newInstance();
    tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    Transformer transformer = tf.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, omitXMLDeclaration ? "yes" : "no");
    transformer.transform(new DOMSource(node), new StreamResult(sw));
    return sw.toString();
  }

  public static class SchemaValidationErrors implements ErrorHandler {
    public final List<SAXParseException> error = new ArrayList<>();

    public final List<SAXParseException> fatal = new ArrayList<>();

    public final List<SAXParseException> warning = new ArrayList<>();

    @Override
    public void error(SAXParseException exception) {
      error.add(exception);
    }

    @Override
    public void fatalError(SAXParseException exception) {
      fatal.add(exception);
    }

    @Override
    public void warning(SAXParseException exception) {
      warning.add(exception);
    }
  }
}
