package com.catherine.securitysample.SafetyNet;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Locale;

/**
 * Created by Catherine on 2017/6/30.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class AttestationResult {
    private boolean ctsProfileMatch;

    private boolean basicIntegrity;

    private long timestampMs;

    private String nonce;

    private String apkDigestSha256;

    private String[] apkCertificateDigestSha256;

    private String apkPackageName;

    public AttestationResult(String payload) throws JSONException {
        final String[] body = payload.split("\\.");
        String decodedPayload = new String(Base64.decode(body[1], Base64.DEFAULT));

        JSONObject jo = new JSONObject(decodedPayload);
        nonce = jo.optString("nonce", "");
        apkDigestSha256 = jo.optString("apkDigestSha256", "");
        apkPackageName = jo.optString("apkPackageName", "");
        basicIntegrity = jo.optBoolean("basicIntegrity", false);
        ctsProfileMatch = jo.optBoolean("ctsProfileMatch", false);
        timestampMs = jo.optLong("timestampMs", 0);
        JSONArray ja = jo.optJSONArray("apkCertificateDigestSha256");
        if (ja != null) {
            String[] certDigests = new String[ja.length()];
            for (int i = 0; i < ja.length(); i++) {
                certDigests[i] = ja.getString(i);
            }
            apkCertificateDigestSha256 = certDigests;
        }
    }

    public boolean isCtsProfileMatch() {
        return ctsProfileMatch;
    }

    public boolean isBasicIntegrity() {
        return basicIntegrity;
    }

    public long getTimestampMs() {
        return timestampMs;
    }


    public String getNonce() {
        return nonce;
    }

    public String getApkDigestSha256() {
        return apkDigestSha256;
    }

    public String[] getApkCertificateDigestSha256() {
        return apkCertificateDigestSha256;
    }

    public String getApkPackageName() {
        return apkPackageName;
    }

    public String getFormattedString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (String s : getApkCertificateDigestSha256()) {
            sb.append(s);
            sb.append(", ");
        }
        sb.delete(sb.length() - 2, sb.length());
        sb.append("]");
        SimpleDateFormat newFormat = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss", Locale.TAIWAN);
        String formattedTime = newFormat.format(getTimestampMs());
        return String.format("Request Time:\n%s\n\nNonce:\n%s\n\nPackageName:\n%s\n\nApkCertificateDigestSha256:\n%s\n\nApkDigestSha256:\n%s\n\nctsProfileMatch:\n%s\n\nbasicIntegrity:\n%s", formattedTime, getNonce(), getApkPackageName(), sb.toString(), getApkDigestSha256(), isCtsProfileMatch(), isBasicIntegrity());
    }

    @Override
    public String toString() {
        return "AttestationJWTBody [ctsProfileMatch = " + ctsProfileMatch + ", basicIntegrity = " + basicIntegrity + ", timestampMs = " + timestampMs + ", nonce = " + nonce + ", apkDigestSha256 = " + apkDigestSha256 + ", apkCertificateDigestSha256 = " + apkCertificateDigestSha256 + ", apkPackageName = " + apkPackageName + "]";
    }
}
