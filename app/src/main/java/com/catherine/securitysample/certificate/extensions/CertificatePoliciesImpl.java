package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.CertificatePolicies;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Catherine
 *
 */
public class CertificatePoliciesImpl implements CertificatePolicies {
	private List<String> certificatePolicyIds;

	public CertificatePoliciesImpl(X509Certificate cert) throws IOException {
		certificatePolicyIds = new ArrayList<>();
		byte[] extVal = cert.getExtensionValue(Extension.certificatePolicies.getId());
		if (extVal == null)
			return;
		org.bouncycastle.asn1.x509.CertificatePolicies cf = org.bouncycastle.asn1.x509.CertificatePolicies
				.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		PolicyInformation[] information = cf.getPolicyInformation();
		for (PolicyInformation p : information) {
			ASN1ObjectIdentifier aIdentifier = p.getPolicyIdentifier();
			certificatePolicyIds.add(aIdentifier.getId());
		}
	}

	@Override
	public List<String> getCertificatePolicyIds() {
		return certificatePolicyIds;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OIDMap.getName(Extension.certificatePolicies.getId()));
		sb.append(" [\n");
		for (int i = 0; i < certificatePolicyIds.size(); i++) {
			sb.append("CertificatePolicyId:");
			sb.append(OIDMap.getName(certificatePolicyIds.get(i)));
			sb.append("\n");
		}
		sb.append("]\n");
		return sb.toString();
	}
}
