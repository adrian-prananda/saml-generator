package com.rackspace.saml;

import java.io.ByteArrayOutputStream;
import java.util.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;


public class SamlAssertionProducer {

	private String privateKeyLocation;
	private String publicKeyLocation;
	private CertManager certManager = new CertManager();

	public Response createSAMLResponse(final String subjectId, final DateTime authenticationTime,
			                           final String audienceUri, final HashMap<String, List<String>> attributes, String issuer, Integer samlAssertionDays, Boolean signResponse, Boolean signAssertion) {

		try {
			DefaultBootstrap.bootstrap();

			Signature signatureForAssertion = null;
			Signature signatureForResponse = null;
			Status status = createStatus();
			Issuer responseIssuer = null;
			Issuer assertionIssuer = null;
			Subject subject = null;
			AttributeStatement attributeStatement = null;
			Audience audience = null;

			if (issuer != null) {
				responseIssuer = createIssuer(issuer);
				assertionIssuer = createIssuer(issuer);
			}

			if (subjectId != null) {
				subject = createSubject(subjectId, samlAssertionDays);
			}

			if (attributes != null && attributes.size() != 0) {
				attributeStatement = createAttributeStatement(attributes);
			}

			AuthnStatement authnStatement = createAuthnStatement(authenticationTime);
			if (audienceUri != null) {
				audience = new AudienceBuilder().buildObject();
				audience.setAudienceURI((audienceUri));
			}
			Assertion assertion = createAssertion(new DateTime(), subject, assertionIssuer, audience, authnStatement, attributeStatement);
			if (signAssertion) {
				signatureForAssertion = createSignature();
				assertion.setSignature(signatureForAssertion);
			}

			Response response = createResponse(new DateTime(), responseIssuer, status, assertion);
			if (signResponse) {
				signatureForResponse = createSignature();
				response.setSignature(signatureForResponse);
			}

			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(response);

			if (signatureForAssertion != null) {
				Signer.signObject(signatureForAssertion);
			}

			if (signatureForResponse != null) {
				Signer.signObject(signatureForResponse);
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);

			return response;

		} catch (Throwable t) {
			t.printStackTrace();
			return null;
		}
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public String getPublicKeyLocation() {
		return publicKeyLocation;
	}

	public void setPublicKeyLocation(String publicKeyLocation) {
		this.publicKeyLocation = publicKeyLocation;
	}

	private Response createResponse(final DateTime issueDate, Issuer issuer, Status status, Assertion assertion) {
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.getAssertions().add(assertion);
		return response;
	}

	private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, Audience audience, AuthnStatement authnStatement,
			                          AttributeStatement attributeStatement) {
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);
		Conditions c = new ConditionsBuilder().buildObject();
		c.getConditions().add(new OneTimeUseBuilder().buildObject());

		AudienceRestriction audienceR = new AudienceRestrictionBuilder().buildObject();

		audienceR.getAudiences().add(audience);
		c.getAudienceRestrictions().add(audienceR);
		assertion.setConditions(c);


		if (authnStatement != null)
			assertion.getAuthnStatements().add(authnStatement);

		if (attributeStatement != null)
			assertion.getAttributeStatements().add(attributeStatement);

		return assertion;
	}

	private Issuer createIssuer(final String issuerName) {
		// create Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);
		return issuer;
	}

	private Subject createSubject(final String subjectId, final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);

		// create name element
		NameIDBuilder nameIdBuilder = new NameIDBuilder();
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(subjectId);
		nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

		SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
		subjectConfirmationData.setNotOnOrAfter(currentDate);

		SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		// create subject element
		SubjectBuilder subjectBuilder = new SubjectBuilder();
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}

	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		// create authcontextclassref object
		AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef classRef = classRefBuilder.buildObject();
		classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		// create authcontext object
		AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = authContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(classRef);

		// create authenticationstatement object
		AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		AuthnStatement authnStatement = authStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);

		return authnStatement;
	}

	private AttributeStatement createAttributeStatement(HashMap<String, List<String>> attributes) {
		// create authenticationstatement object
		AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

		AttributeBuilder attributeBuilder = new AttributeBuilder();
		if (attributes != null) {
			for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(entry.getKey());

				for (String value : entry.getValue()) {
					XSStringBuilder stringBuilder = new XSStringBuilder();
					XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
					attributeValue.setValue(value);
					attribute.getAttributeValues().add(attributeValue);
				}

				attributeStatement.getAttributes().add(attribute);
			}
		}

		return attributeStatement;
	}

	private Status createStatus() {
		StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}

	private Signature createSignature() throws Throwable {
		if (publicKeyLocation != null && privateKeyLocation != null) {
			SignatureBuilder builder = new SignatureBuilder();
			Signature signature = builder.buildObject();
			signature.setSigningCredential(certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			return signature;
		}

		return null;
	}
}
