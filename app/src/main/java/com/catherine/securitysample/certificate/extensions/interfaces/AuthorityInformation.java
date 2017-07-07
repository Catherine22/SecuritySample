package com.catherine.securitysample.certificate.extensions.interfaces;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AuthorityInformation {
	 List<String> getAccessIDs();

	 List<String> getAccessMethods();

	 List<String> getAccessLocations();

	 X509Certificate getCaIssuersCert(String issuerUrl) throws CertificateException, IOException;

}
