package com.catherine.securitysample.certificate.extensions.interfaces;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public interface CRLDistributionPoints {
    List<String> getURINames();

    X509Certificate getCaIssuersCert(String URIName) throws CertificateException, IOException;
}
