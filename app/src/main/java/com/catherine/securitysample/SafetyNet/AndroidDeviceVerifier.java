package com.catherine.securitysample.SafetyNet;

import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

/**
 * Created by Catherine on 2017/7/3.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class AndroidDeviceVerifier {

    private static final String TAG = "AndroidDeviceVerifier";

    //used to verify the safety net response - 10,000 requests/day free
    private static final String GOOGLE_VERIFICATION_URL = "https://www.googleapis.com/androidcheck/v1/attestations/verify?key=";

    private final String apiKey;
    private final String signatureToVerify;
    private AndroidDeviceVerifierCallback callback;

    public interface AndroidDeviceVerifierCallback {
        void error(String s);

        void success(boolean isValidSignature);
    }

    public AndroidDeviceVerifier(@NonNull String apiKey, @NonNull String signatureToVerify) {
        this.apiKey = apiKey;
        this.signatureToVerify = signatureToVerify;
    }

    public void verify(AndroidDeviceVerifierCallback androidDeviceVerifierCallback) {
        callback = androidDeviceVerifierCallback;
        AndroidDeviceVerifierTask task = new AndroidDeviceVerifierTask();
        task.execute();
    }


    private class AndroidDeviceVerifierTask extends AsyncTask<Void, Void, Boolean> {

        private String errorMessage;

        @Override
        protected Boolean doInBackground(Void... params) {

//            Log.d(TAG, "signatureToVerify:" + signatureToVerify);

            try {
                URL verifyApiUrl = new URL(GOOGLE_VERIFICATION_URL + apiKey);

                HttpsURLConnection urlConnection = (HttpsURLConnection) verifyApiUrl.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setRequestProperty("Content-Type", "application/json");
                urlConnection.setConnectTimeout(10000);
                urlConnection.setReadTimeout(5000);
                urlConnection.setDoOutput(true);
                //build post body { "signedAttestation": "<output of getJwsResult()>" }
                String requestJsonBody = "{ \"signedAttestation\": \"" + signatureToVerify + "\"}";
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
                    if (responseRoot.has("isValidSignature") && responseRoot.getBoolean("isValidSignature"))
                        return true;
                    else {
                        errorMessage = "Error JSON response.";
                        return false;
                    }
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
                        if ("dailyLimitExceeded".equals(jo.optString("reason", ""))) {
                            // In this case, it means you've run out of the quotas. You can verify the compatibility check response by yourself.
                            //Let's assume this JWS result is legal.
                            return true;
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
        protected void onPostExecute(Boolean aBoolean) {
            if (aBoolean)
                callback.success(aBoolean);
            else
                callback.error(errorMessage);
        }
    }

}