package com.catherine.securitysample.certificate.extensions;

import com.catherine.securitysample.certificate.extensions.interfaces.BasicConstraints;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 
 * @author Catherine
 *
 */
public class BasicConstraintsImpl implements BasicConstraints {
	/**
	 * 表明该证书可否作为CA证书签发下一级证书
	 */
	private boolean isCA;
	/**
	 * 只有当CA=true时才有效，表明具体可以签发的证书级别
	 */
	private BigInteger pathLen;

	public BasicConstraintsImpl(X509Certificate cert) throws CertificateException, IOException {
		byte[] extVal = cert.getExtensionValue(Extension.basicConstraints.getId());
		if (extVal == null)
			return;
		org.bouncycastle.asn1.x509.BasicConstraints bc = org.bouncycastle.asn1.x509.BasicConstraints
				.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		isCA = bc.isCA();
		pathLen = bc.getPathLenConstraint();
	}

	@Override
	public boolean isCA() {
		return isCA;
	}

	@Override
	public BigInteger getPathLen() {
		return pathLen;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(OIDMap.getName(Extension.basicConstraints.getId()));
		sb.append(" [\n");
		sb.append("isCA:");
		sb.append(isCA);
		sb.append("\nPathLen:");
		if (pathLen == null)
			sb.append("undefined");
		else
			sb.append(pathLen);
		sb.append("\n]\n");
		return sb.toString();
	}
}
