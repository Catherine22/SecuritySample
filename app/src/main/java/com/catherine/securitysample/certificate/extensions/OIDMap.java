package com.catherine.securitysample.certificate.extensions;

import java.util.HashMap;
import java.util.Map;

/**
 * OID查表，这边只列举几个
 * 
 * @author Catherine
 *
 */
public class OIDMap {
	private final static Map<String, String> names = new HashMap<>();
	private final static Map<String, String> descriptions = new HashMap<>();
	static {
		names.put("1.3.6.1.5.5.7.3.1", "serverAuth");
		names.put("1.3.6.1.5.5.7.3.2", "clientAuth");
		names.put("1.3.6.1.5.5.7.3.3", "codeSigning");
		names.put("1.3.6.1.5.5.7.3.4", "emailProtection");
		names.put("1.3.6.1.5.5.7.3.5", "ipsecEndSystem");
		names.put("1.3.6.1.5.5.7.3.6", "ipsecTunnel");
		names.put("2.23.140.1.2.2", "extended-validation");
		names.put("1.3.6.1.4.1.11129.2.5.1", "Google Internet Authority G2");
		names.put("1.3.6.1.5.5.7.48.2", "caIssuers");
		names.put("1.3.6.1.5.5.7.48.1", "OCSP");
		names.put("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
		names.put("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");
		names.put("2.5.29.14", "Subject Key Identifier");
		names.put("2.5.29.17", "Subject Alternative Name");
		names.put("2.5.29.19", "Basic Constraints");
		names.put("2.5.29.31", "CRL Distribution Points");
		names.put("2.5.29.32", "Certificate Policies");
		names.put("2.5.29.35", "Authority Key Identifier");
		names.put("2.5.29.37", "Extended key usage");

		descriptions.put("1.3.6.1.5.5.7.3.1", "Indicates that a certificate can be used as an SSL server certificate.");
		descriptions.put("1.3.6.1.5.5.7.3.2", "Indicates that a certificate can be used as an SSL client certificate.");
		descriptions.put("1.3.6.1.5.5.7.3.3", "Indicates that a certificate can be used for code signing.");
		descriptions.put("1.3.6.1.5.5.7.3.4",
				"Indicates that a certificate can be used for protecting email (signing, encryption, key agreement).");
		descriptions.put("1.3.6.1.5.5.7.3.5", "URL for further info: http://www.ietf.org/rfc/rfc2459.txt");
		descriptions.put("1.3.6.1.5.5.7.3.6", "URL for further info: http://www.ietf.org/rfc/rfc2459.txt");
		descriptions.put("2.23.140.1.2.2",
				"CA-Browser Forum, Certificate Policy, Extended Validation Baseline Requirements, Organization Validated");
		descriptions.put("1.3.6.1.4.1.11129.2.5.1",
				"https://static.googleusercontent.com/media/pki.google.com/en//GIAG2-CPS-1.0.pdf");
		descriptions.put("1.3.6.1.5.5.7.48.2", "URL for further info: http://www.ietf.org/rfc/rfc2459.txt");
		descriptions.put("1.3.6.1.5.5.7.48.1",
				"Online Certificate Status Protokoll\nSee also the OID Repository website reference for 1.3.6.1.5.5.7.48.1");
		descriptions.put("1.2.840.113549.1.1.11",
				"SHA256 with RSA Encryption\nURL for further info: http://asn1.elibel.tm.fr/cgi-bin/oid/display?oid=1.2.840.113549.1.1.11&action=display");
		descriptions.put("1.3.6.1.5.5.7.1.1", "URL for further info: http://www.ietf.org/rfc/rfc2459.txt");
		descriptions.put("2.5.29.14",
				"This extension identifies the public key being certified. It enables distinct keys used by the same subject to be differentiated (e.g., as key updating occurs).\nA key identifer shall be unique with respect to all key identifiers for the subject with which it is used. This extension is always non-critical.");
		descriptions.put("2.5.29.17",
				"This extension contains one or more alternative names, using any of a variety of name forms, for the entity that is bound by the CA to the certified public key.\nThis extension may, at the option of the certificate issuer, be either critical or non-critical. An implementation which supports this extension is not required to be able to process all name forms. If the extension is flagged critical, at least one of the name forms that is present shall be recognized and processed, otherwise the certificate shall be considered invalid.");
		descriptions.put("2.5.29.19",
				"This extension indicates if the subject may act as a CA, with the certified public key being used to verify certificate signatures. If so, a certification path length constraint may also be specified.");
		descriptions.put("2.5.29.31",
				"This extension field shall be used only as a certificate extension and may be used in both CA-certificates and end-entity certificates. This field identifies the CRL distribution point or points to which a certificate user should refer to ascertain if the certificate has been revoked. A certificate user can obtain a CRL from an applicable distribution point or it can obtain a current complete CRL from the CA directory entry.");
		descriptions.put("2.5.29.32",
				"This extension lists certificate policies, recognized by the issuing CA, that apply to the certificate, together with optional qualifier information pertaining to these certificate policies. Typically, different certificate policies will relate to different applications which may use the certified key.");
		descriptions.put("2.5.29.35",
				"This extension may be used either as a certificate or CRL extension. It identifies the public key to be used to verify the signature on this certificate or CRL. It enables distinct keys used by the same CA to be distinguished (e.g., as key updating occurs).");
		descriptions.put("2.5.29.37",
				"This field indicates one or more purposes for which the certified public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension field.");
	}

	public static String getName(String OID) {
		return names.get(OID);
	}

	public static String getDescription(String OID) {
		return descriptions.get(OID);
	}
}
