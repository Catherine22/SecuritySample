package com.catherine.securitysample.SafetyNet;

import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

/**
 * Validates the result with Android Device Verification API.
 * <p>
 * Note: This only validates that the provided JWS (JSON Web Signature) message was received from the actual SafetyNet service.
 * It does *not* verify that the payload data matches your original compatibility check request.
 * POST to https://www.googleapis.com/androidcheck/v1/attestations/verify?key=<your API key>
 * <p>
 * More info see {link https://developer.android.com/google/play/safetynet/start.html#verify-compat-check}
 */
public class AndroidDeviceVerifier {

    private static final String TAG = AndroidDeviceVerifier.class.getSimpleName();

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

        private Exception error;

        @Override
        protected Boolean doInBackground(Void... params) {

            //Log.d(TAG, "signatureToVerify:" + signatureToVerify);

            try {
                URL verifyApiUrl = new URL(GOOGLE_VERIFICATION_URL + apiKey);

                HttpsURLConnection urlConnection = (HttpsURLConnection) verifyApiUrl.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setRequestProperty("Content-Type", "application/json");

                //build post body { "signedAttestation": "<output of getJwsResult()>" }
                String requestJsonBody = "{ \"signedAttestation\": \"" + signatureToVerify + "\"}";
                byte[] outputInBytes = requestJsonBody.getBytes("UTF-8");
                OutputStream os = urlConnection.getOutputStream();
                os.write(outputInBytes);
                os.close();

                urlConnection.connect();

                //resp ={ “isValidSignature”: true }
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
                if (responseRoot.has("isValidSignature")) {
                    return responseRoot.getBoolean("isValidSignature");
                }
            } catch (Exception e) {
                //something went wrong requesting validation of the JWS Message
                error = e;
                Log.e(TAG, "problem validating JWS Message :" + e.getMessage(), e);
                return false;
            }
            return false;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            if (error != null) {
                callback.error(error.getMessage());
            } else {
                callback.success(aBoolean);
            }
        }
    }

}