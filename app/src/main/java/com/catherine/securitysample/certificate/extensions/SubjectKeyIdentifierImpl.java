package com.catherine.securitysample.certificate.extensions;

import android.util.Base64;

import com.catherine.securitysample.certificate.extensions.interfaces.SubjectKeyIdentifier;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * @author Catherine
 */
public class SubjectKeyIdentifierImpl implements SubjectKeyIdentifier {

    private byte[] keyIdentifier;
    private boolean lock;

    public SubjectKeyIdentifierImpl(X509Certificate cert) throws IOException {
        byte[] extVal = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (extVal == null) {
            lock = true;
            return;
        }
        org.bouncycastle.asn1.x509.SubjectKeyIdentifier identifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier
                .getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
        keyIdentifier = identifier.getKeyIdentifier();
    }

    public byte[] getSubjectKeyIdentifier() {
        return keyIdentifier;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(OIDMap.getName(Extension.subjectKeyIdentifier.getId()));
        sb.append(" [\n");
        if (!lock) {
            sb.append("KeyIdentifierImpl [\n");
            sb.append(Base64.encodeToString(keyIdentifier, Base64.DEFAULT));
            sb.append("]\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

}
