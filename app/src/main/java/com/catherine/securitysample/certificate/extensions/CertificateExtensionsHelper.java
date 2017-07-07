package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.AuthorityInformation;
import com.catherine.securitysample.certificate.extensions.interfaces.BasicConstraints;
import com.catherine.securitysample.certificate.extensions.interfaces.CRLDistributionPoints;
import com.catherine.securitysample.certificate.extensions.interfaces.CertificatePolicies;
import com.catherine.securitysample.certificate.extensions.interfaces.ExtendedKeyUsage;
import com.catherine.securitysample.certificate.extensions.interfaces.KeyIdentifier;
import com.catherine.securitysample.certificate.extensions.interfaces.SubjectAlternativeName;
import com.catherine.securitysample.certificate.extensions.interfaces.SubjectKeyIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * 
 * @author Catherine
 *
 */
public class CertificateExtensionsHelper implements AuthorityInformation, BasicConstraints, CertificatePolicies,
		CRLDistributionPoints, ExtendedKeyUsage, KeyIdentifier, SubjectAlternativeName, SubjectKeyIdentifier {
	private AuthorityInformationImpl authorityInformation;
	private KeyIdentifierImpl keyIdentifier;
	private BasicConstraintsImpl basicConstraints;
	private CRLDistributionPointsImpl crlDistributionPoints;
	private CertificatePoliciesImpl certificatePolicies;
	private ExtendedKeyUsageImpl extendedKeyUsage;
	private SubjectAlternativeNameImpl subjectAlternativeName;
	private SubjectKeyIdentifierImpl subjectKeyIdentifier;

	public CertificateExtensionsHelper(X509Certificate cert) throws CertificateException, IOException {
		authorityInformation = new AuthorityInformationImpl(cert);
		keyIdentifier = new KeyIdentifierImpl(cert);
		basicConstraints = new BasicConstraintsImpl(cert);
		crlDistributionPoints = new CRLDistributionPointsImpl(cert);
		certificatePolicies = new CertificatePoliciesImpl(cert);
		extendedKeyUsage = new ExtendedKeyUsageImpl(cert);
		subjectAlternativeName = new SubjectAlternativeNameImpl(cert);
		subjectKeyIdentifier = new SubjectKeyIdentifierImpl(cert);
	}

	@Override
	public List<String> getAccessIDs() {
		return authorityInformation.getAccessIDs();
	}

	@Override
	public List<String> getAccessMethods() {
		return authorityInformation.getAccessMethods();
	}

	@Override
	public List<String> getAccessLocations() {
		return authorityInformation.getAccessLocations();
	}

	@Override
	public X509Certificate getCaIssuersCert(String issuerUrl) throws CertificateException, IOException {
		URL url = new URL(issuerUrl);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) certificateFactory.generateCertificate(url.openStream());
	}

	@Override
	public boolean isCA() {
		return basicConstraints.isCA();
	}

	@Override
	public BigInteger getPathLen() {
		return basicConstraints.getPathLen();
	}

	@Override
	public List<String> getCertificatePolicyIds() {
		return certificatePolicies.getCertificatePolicyIds();
	}

	@Override
	public List<String> getURINames() {
		return crlDistributionPoints.getURINames();
	}

	@Override
	public List<String> getKeyPurposeIds() {
		return extendedKeyUsage.getKeyPurposeIds();
	}

	@Override
	public byte[] getKeyIdentifier() {
		return keyIdentifier.getKeyIdentifier();
	}

	@Override
	public List<String> getDNSNames() {
		return subjectAlternativeName.getDNSNames();
	}

	@Override
	public byte[] getSubjectKeyIdentifier() {
		return subjectKeyIdentifier.getSubjectKeyIdentifier();
	}

	@Override
	public String toString() {
		return String.format("%s%s%s%s%s%s%s%s", authorityInformation.toString(), keyIdentifier.toString(),
				basicConstraints.toString(), crlDistributionPoints.toString(), certificatePolicies.toString(),
				extendedKeyUsage.toString(), subjectAlternativeName.toString(), subjectKeyIdentifier.toString());
	}

}
