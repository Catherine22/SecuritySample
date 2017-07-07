package com.catherine.securitysample.certificate.extensions.interfaces;

import java.math.BigInteger;

public interface BasicConstraints {
	/**
	 * 表明该证书可否作为CA证书签发下一级证书
	 */
	 boolean isCA();

	/**
	 * 只有当CA=true时才有效，表明具体可以签发的证书级别
	 */
	 BigInteger getPathLen();
}
