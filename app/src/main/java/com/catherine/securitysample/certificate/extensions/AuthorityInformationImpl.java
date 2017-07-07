package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.AuthorityInformation;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Catherine
 *
 */
public class AuthorityInformationImpl implements AuthorityInformation {
	private List<String> accessIDs;
	private List<String> accessMethods;
	private List<String> accessLocations;

	/**
	 * 
	 * @param cert
	 * @throws CertificateException
	 * @throws IOException
	 */
	public AuthorityInformationImpl(X509Certificate cert) throws IOException {
		accessIDs = new ArrayList<>();
		accessMethods = new ArrayList<>();
		accessLocations = new ArrayList<>();
		byte[] extVal = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (extVal == null)
			return;

		AuthorityInformationAccess aia = AuthorityInformationAccess
				.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		// check if there is a URL to issuer's certificate
		AccessDescription[] descriptions = aia.getAccessDescriptions();
		for (AccessDescription ad : descriptions) {
			// check if it's a URL to issuer's certificate
			if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
				GeneralName location = ad.getAccessLocation();
				if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
					String issuerUrl = location.getName().toString();
					// http URL to issuer (test in your browser to see if
					// it's a valid certificate)
					// you can use java.net.URL.openStream() to create a
					// InputStream and create the certificate with your
					// CertificateFactory
					accessMethods.add(OIDMap.getName(X509ObjectIdentifiers.id_ad_caIssuers.getId()));
					accessIDs.add(X509ObjectIdentifiers.id_ad_caIssuers.getId());
					accessLocations.add(issuerUrl);
				}
			}

			else if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp)) {
				GeneralName location = ad.getAccessLocation();
				if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
					String issuerUrl = location.getName().toString();
					accessMethods.add(OIDMap.getName(X509ObjectIdentifiers.id_ad_ocsp.getId()));
					accessIDs.add(X509ObjectIdentifiers.id_ad_ocsp.getId());
					accessLocations.add(issuerUrl);

				}
			}
		}
	}

	@Override
	public List<String> getAccessIDs() {
		return accessIDs;
	}

	@Override
	public List<String> getAccessMethods() {
		return accessMethods;
	}

	@Override
	public List<String> getAccessLocations() {
		return accessLocations;
	}

	@Override
	public X509Certificate getCaIssuersCert(String issuerUrl) throws CertificateException, IOException {
		URL url = new URL(issuerUrl);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) certificateFactory.generateCertificate(url.openStream());
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OIDMap.getName(Extension.authorityInfoAccess.getId()));
		sb.append(" [\n");
		for (int i = 0; i < accessIDs.size(); i++) {
			sb.append("accessMethod:");
			sb.append(accessMethods.get(i));
			sb.append("\naccessLocation (URIName):");
			sb.append(accessLocations.get(i));
			sb.append("\n");
		}
		sb.append("]\n");
		return sb.toString();
	}

}
