package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.ExtendedKeyUsage;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
public class ExtendedKeyUsageImpl implements ExtendedKeyUsage{
	private List<String> keyPurposeIds;

	public ExtendedKeyUsageImpl(X509Certificate cert) throws IOException {
		keyPurposeIds = new ArrayList<>();
		byte[] extVal = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
		if (extVal == null)
			return;
		org.bouncycastle.asn1.x509.ExtendedKeyUsage usage = org.bouncycastle.asn1.x509.ExtendedKeyUsage
				.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		KeyPurposeId[] usages = usage.getUsages();
		for (int i = 0; i < usages.length; i++) {
			keyPurposeIds.add(usages[i].getId());
		}
	}

	@Override
	public List<String> getKeyPurposeIds() {
		return keyPurposeIds;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OIDMap.getName(Extension.extendedKeyUsage.getId()));
		sb.append(" [\n");
		for (int i = 0; i < keyPurposeIds.size(); i++) {
			sb.append("keyPurposeIds:");
			sb.append(OIDMap.getName(keyPurposeIds.get(i)));
			sb.append("\n");
		}
		sb.append("]\n");
		return sb.toString();
	}
}
