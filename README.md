SAML Response Generator
=======================

This is a small utility program that makes it easy to generate SAML responses for testing.

Creating Private and Public Keys for Testing
--------------------------------------------

You will need to generate a private and public key to use for generating saml assertions. The following steps are used for creating the keys:
```
#create the keypair
openssl req -new -x509 -days 3652 -nodes -out saml.crt -keyout saml.pem

#convert the private key to pkcs8 format
openssl pkcs8 -topk8 -inform PEM -outform DER -in saml.pem -out saml.pkcs8 -nocrypt
```

Put the .crt file to the **X509 Signing Certificate** section in Auth0 SAML Enterprise Connection setup.

Command line tool
-----------------

You will need to create the jar file in order to use the command line tool. cd to saml-tutorial then run 'mvn package' to create a jar file called 'saml-generator-1.0.jar'. This jar file will be used to create saml assertions.

Usage
-----

```
java -jar target/saml-generator-1.0.jar [-audience <arg>] [-domain <arg>] [-email <arg>]
       [-issuer <arg>] [-privateKey <arg>] [-publicKey <arg>] [-roles
       <arg>] [-samlAssertionExpirationDays <arg>] [-signAssertion <arg>]
       [-signResponse <arg>] [-subject <arg>]
```

```
-issuer
The URI of the issuer for the saml assertion.

-subject
The username of the federated user.

-domain
The domain ID for the federated user.

-roles
A comma separated list of role names for the federated user.

-email
The email address of the federated user.

-publicKey
THe path to the location of the public key to decrypt assertions

-privateKey
The path to the location of the private key to use to sign assertions

-samlAssertionExpirationDays
How long before the assertion is no longer valid

-signAssertion
If the assertion should be signed or not

-signResponse
If the response should be signed or not
```

Example
-------
```
java -jar target/saml-generator-1.0.jar -domain 7719 -issuer 'http://some.company.com' -privateKey saml.pkcs8 -publicKey saml.crt -roles 'role1' -samlAssertionExpirationDays 5 -subject samlUser1 -audience urn:auth0:dev-pqvcfqsnjembwauf:okta-idp-test-local-1 -signResponse true -signAssertion true
```

Output:
```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="8e05ca3c-3ef5-45d7-b593-a00b3062dcda" IssueInstant="2022-11-18T20:03:30.061Z" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://some.company.com</saml2:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#8e05ca3c-3ef5-45d7-b593-a00b3062dcda">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>IJpGo7Ipyd+FXbxet+LeLvLA1Sc=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>F3QC/e8k+zGw7rAPPON6uuyiDDAHF6tIqAnxTDVYoYFdB6sHOFApxXeczwJG9YAM3RQ7e9+xBCsmzIU8hUaRZMZo+WLaMYiOGI8Ak6iRnrlLtHDlM164hB13FnMp3qRnqYYY1u6tO8jdQ5Emcd1i+1xk/u+PeNmTvqASwTHxy+AGV5vzbRuVi70tSbS8mkis+CNXXX0s3GoF+zQYm+LGB7rm49xxzFnF2nx/5ChiQ+RUx01BgbLXjRALNCHkNKDSWNMCjcGkzAUnQERRdw2wONiMKWg0gvKYqpz/zZ+sy2cIkKCuJACmMYp1VOKmhpePu6aLokRXc4W4eXnMvdXVGA==</ds:SignatureValue>
  </ds:Signature>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="e9aa1853-0911-40d0-9175-1e8899f09438" IssueInstant="2022-11-18T20:03:30.044Z" Version="2.0">
    <saml2:Issuer>http://some.company.com</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <ds:Reference URI="#e9aa1853-0911-40d0-9175-1e8899f09438">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
              <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
            </ds:Transform>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>AMeC6Ua65RKBr0fpZHrrl4gvvTg=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>M9cgr2B7Uq5MXmWWmeBkOY1JSCokzolaJpyTpnEnT6yyDGXieUC4p6RBtCxSYoq33+qRAcx0zrvEXvVVBmH3G9QbhxVYGADqo9XNDzcTPa6Otqs37wPwQVR7PE20+AznET7dL1eG6q/eL89dBmUX7FF7Gyrg1I8zENk1If2HAMZ6SZ7dMKPf37euw6nfeDIkz/BSwODuxOy2KW9H8xYKm5ySwgdThLfQdi4ehTzu2i+VMRhwetfatCrsNVVC7LOm6FsdLliaWpIM4WBSPiFkNb9q+ZyVVTJ9ghahZ+BmqY7XGJKXi4bS9vn2dyYdIwCOi2zuIVVPLtDDY00fTbZYUA==</ds:SignatureValue>
    </ds:Signature>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">samlUser1</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="2022-11-23T20:03:30.040Z"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions>
      <saml2:OneTimeUse/>
      <saml2:AudienceRestriction>
        <saml2:Audience>urn:auth0:dev-pqvcfqsnjembwauf:okta-idp-test-local-1</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="2022-11-18T20:03:28.354Z">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="domain">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">7719</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="roles">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">role1</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
```
