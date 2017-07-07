package com.catherine.securitysample.safety_net;

import android.util.Base64;

import com.catherine.securitysample.certificate.CertificatesManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Catherine on 2017/7/7.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class JwsHelper {
    private String[] jws;
    private String decodedHeader;

    public JwsHelper(String jws) {
        this.jws = jws.split("\\.");
        decodedHeader = new String(Base64.decode(this.jws[0], Base64.DEFAULT));
    }

    public String getDecodedHeader() {
        return decodedHeader;
    }

    public String getDecodedPayload() {
        return new String(Base64.decode(jws[1], Base64.DEFAULT));
    }

    public String getSignature() {
        return jws[2];
    }

    public String getAlg() throws JSONException {
        JSONObject jo = new JSONObject(decodedHeader);
        return jo.optString("alg", "");
    }

    public List<X509Certificate> getX5CCertificates()
            throws JSONException, CertificateException, FileNotFoundException {
        JSONObject jo = new JSONObject(decodedHeader);
        JSONArray ja = jo.optJSONArray("x5c");
        if (ja != null) {
            List<X509Certificate> certs = new ArrayList<>();
            for (int i = 0; i < ja.length(); i++) {
                certs.add(CertificatesManager.getX509Certificate(ja.getString(i)));
            }
            return certs;
        }
        return null;
    }

    /**
     * The RSA SHA-256 signature for a JWS is validated as follows:<br>
     * <br>
     * Take the JWS Crypto Output and base64url decode it into a byte array. If
     * decoding fails, the signed content MUST be rejected. Submit the UTF-8
     * representation of the JWS Signing Input and the public key corresponding
     * to the private key used by the signer to the RSASSA-PKCS1-V1_5-VERIFY
     * algorithm using SHA-256 as the hash function. If the validation fails,
     * the signed content MUST be rejected. <br>
     * <br>
     * reference:http://self-issued.info/docs/draft-jones-json-web-signature-01.
     * html
     *
     * @param alg
     * @return
     */
    public boolean verifySignature(String alg) {
        try {
            Signature sig = Signature.getInstance(alg);
            sig.initVerify(getX5CCertificates().get(0));
            byte[] signature = org.apache.commons.codec.binary.Base64.decodeBase64(getSignature());
            String content = jws[0] + "." + jws[1];
            sig.update(content.getBytes());
            return sig.verify(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return false;

    }
}
