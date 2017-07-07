package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.SubjectAlternativeName;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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
public class SubjectAlternativeNameImpl implements SubjectAlternativeName {
	private List<String> DNSNames;

	public SubjectAlternativeNameImpl(X509Certificate cert) throws IOException {
		DNSNames = new ArrayList<>();
		byte[] extVal = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
		if (extVal == null)
			return;
		GeneralNames gn = GeneralNames.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		GeneralName[] names = gn.getNames();
		for (GeneralName name : names) {
			if (name.getTagNo() == GeneralName.dNSName) {
				String dns = name.getName().toString();
				DNSNames.add(dns);
			}
		}
	}

	@Override
	public List<String> getDNSNames() {
		return DNSNames;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OIDMap.getName(Extension.subjectAlternativeName.getId()));
		sb.append(" [\n");
		for (int i = 0; i < DNSNames.size(); i++) {
			sb.append("DNSName:");
			sb.append(DNSNames.get(i));
			sb.append("\n");
		}
		sb.append("]\n");
		return sb.toString();
	}
}
