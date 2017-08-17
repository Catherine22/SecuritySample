package com.catherine.securitysample.safety_net;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.view.View;
import android.widget.ProgressBar;

import com.catherine.securitysample.Algorithm;
import com.catherine.securitysample.BuildConfig;
import com.catherine.securitysample.Settings;
import com.catherine.securitysample.certificate.CertificatesManager;
import com.catherine.securitysample.certificate.KeySet;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * Created by Catherine on 2017/7/7.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class AttestationAsyncTask extends AsyncTask<String, Void, Boolean> {
    public final static String TAG = "AttestationAsyncTask";
    private ProgressBar progressBar;
    private boolean runInBackground;
    private Context ctx;
    private String errorMessage;
    private AttestationTaskCallback callback;

    public AttestationAsyncTask(Context ctx, boolean runInBackground, AttestationTaskCallback callback) {
        this.ctx = ctx;
        this.callback = callback;
        this.runInBackground = runInBackground;
    }

    protected void onPreExecute() {
        if (runInBackground) {
            progressBar = new ProgressBar(ctx);
            progressBar.setVisibility(View.VISIBLE);
        }
    }

    @Override
    protected Boolean doInBackground(String... params) {
        String jws = params[0];
        //            Log.d(TAG, "signatureToVerify:" + signatureToVerify);

        try {
            URL verifyApiUrl = new URL(Settings.GOOGLE_VERIFICATION_URL + BuildConfig.API_KEY);

            HttpsURLConnection urlConnection = (HttpsURLConnection) verifyApiUrl.openConnection();
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setConnectTimeout(10000);
            urlConnection.setReadTimeout(5000);
            urlConnection.setDoOutput(true);
            //build post body { "signedAttestation": "<output of getJwsResult()>" }
            String requestJsonBody = "{ \"signedAttestation\": \"" + jws + "\"}";
            byte[] outputInBytes = requestJsonBody.getBytes("UTF-8");
            OutputStream os = urlConnection.getOutputStream();
            os.write(outputInBytes);
            os.close();

            urlConnection.connect();

            //resp ={ “isValidSignature”: true }
            int status = urlConnection.getResponseCode();
            Log.d(TAG, "status:" + status);
            if (status == 200) {
                InputStream is = urlConnection.getInputStream();
                StringBuilder sb = new StringBuilder();
                BufferedReader rd = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = rd.readLine()) != null) {
                    sb.append(line);
                }
                String response = sb.toString();
                Log.d(TAG, "response:" + response);
                JSONObject responseRoot = new JSONObject(response);
                if (responseRoot.optBoolean("isValidSignature", false)) {
                    JwsHelper jwsHelper = new JwsHelper(jws);
                    AttestationResult result = new AttestationResult(jwsHelper.getDecodedPayload());
                    Log.d(TAG, result.toString());

                    List<X509Certificate> certs = jwsHelper.getX5CCertificates();
                    X509Certificate rootCert = CertificatesManager.downloadCaIssuersCert(KeySet.GIAG2_URL);

                    // Just verify one of the certificates which is belonged to "attest.android.com" in this case.
                    boolean isJwsHeaderLegal = false;
                    for (X509Certificate cert : certs) {
                        boolean isValid = CertificatesManager.validate(cert, rootCert);
                        CertificatesManager.printCertificatesInfo(cert);
                        if (isValid == true)
                            isJwsHeaderLegal = true;
                    }

                    // Verify the signature of JWS
                    boolean isJwsSignatureLegal = jwsHelper.verifySignature(Algorithm.ALG_SHA256_WITH_RSA);
                    Log.d(TAG, isJwsHeaderLegal + "," + isJwsSignatureLegal);
                    if (isJwsHeaderLegal && isJwsSignatureLegal) {
                        Log.d(TAG, "Android attestation JWS 通過驗證！");
                        return true;
                    } else {
                        Log.d(TAG, "Android attestation JWS 驗證失败！");
                        return false;
                    }
                } else {
                    errorMessage = "Error JSON response.";
                    return false;
                }
            } else if (status == 400) {
                Log.e(TAG, "error response:400");
                errorMessage = "Please check your API_KEY in gradle";
                return false;
            } else {
                InputStream is = urlConnection.getErrorStream();
                StringBuilder sb = new StringBuilder();
                BufferedReader rd = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = rd.readLine()) != null) {
                    sb.append(line);
                }
                String response = sb.toString();
                Log.e(TAG, "error response:" + response);

                JSONObject responseRoot = new JSONObject(response);
                JSONObject responseBody = responseRoot.getJSONObject("error");
                errorMessage = responseBody.optString("message", "error");

                JSONArray errors = responseBody.getJSONArray("errors");
                for (int i = 0; i < errors.length(); i++) {
                    JSONObject jo = errors.getJSONObject(i);
                    if ("usageLimits".equals(jo.optString("domain", ""))) {
                        // In this case, it means you've run out of the quota. You can verify the compatibility check response by yourself.

                        JwsHelper jwsHelper = new JwsHelper(jws);
                        AttestationResult result = new AttestationResult(jwsHelper.getDecodedPayload());
                        Log.d(TAG, result.toString());

                        List<X509Certificate> certs = jwsHelper.getX5CCertificates();
                        X509Certificate rootCert = CertificatesManager.downloadCaIssuersCert(KeySet.GIAG2_URL);

                        // Just verify one of the certificates which is belonged to "attest.android.com" in this case.
                        boolean isJwsHeaderLegal = false;
                        for (X509Certificate cert : certs) {
                            boolean isValid = CertificatesManager.validate(cert, rootCert);
                            CertificatesManager.printCertificatesInfo(cert);
                            if (isValid == true)
                                isJwsHeaderLegal = true;
                        }

                        // Verify the signature of JWS
                        boolean isJwsSignatureLegal = jwsHelper.verifySignature(Algorithm.ALG_SHA256_WITH_RSA);
                        if (isJwsHeaderLegal && isJwsSignatureLegal) {
                            Log.d(TAG, "Android attestation JWS 通過驗證！");
                            return true;
                        } else {
                            Log.d(TAG, "Android attestation JWS 驗證失败！");
                            return false;
                        }
                    }
                }
                return false;
            }
        } catch (Exception e) {
            errorMessage = "problem validating JWS Message :" + e.getMessage();
            Log.e(TAG, errorMessage, e);
            return false;
        }
    }

    @Override
    protected void onPostExecute(Boolean b) {
        if (b)
            callback.success(b);
        else
            callback.error(errorMessage);
    }
}
