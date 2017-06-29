package com.catherine.securitysample;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.safetynet.HarmfulAppsData;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

/**
 * Created by Catherine on 2017/6/29.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class SafetyNetUtils {
    private final static String TAG = "SafetyNetUtils";
    private Context ctx;
    private Callback callback;
    private GoogleApiClient googleApiClient;

    public SafetyNetUtils(Context ctx, Callback callback) {
        this.ctx = ctx;
        this.callback = callback;
        googleApiClient = new GoogleApiClient.Builder(ctx)
                .addApi(SafetyNet.API)
                .addConnectionCallbacks(googleApiConnectionCallbacks)
                .addOnConnectionFailedListener(googleApiConnectionFailedListener)
                .build();
        googleApiClient.connect();
    }

    public interface Callback {
        void onResponse(String message);
    }

    public void verifyAppsNew() {
        final StringBuilder sb = new StringBuilder();
        SafetyNet.getClient(ctx)
                .isVerifyAppsEnabled()
                .addOnCompleteListener(new OnCompleteListener<SafetyNetApi.VerifyAppsUserResponse>() {
                    @Override
                    public void onComplete(Task<SafetyNetApi.VerifyAppsUserResponse> task) {
                        if (task.isSuccessful()) {
                            SafetyNetApi.VerifyAppsUserResponse result = task.getResult();
                            if (result.isVerifyAppsEnabled()) {
                                sb.append("The Verify Apps feature is enabled.\n");
                            } else {
                                sb.append("The Verify Apps feature is disabled.\n");
                            }
                        } else {
                            sb.append("A general error occurred.\n");
                            Log.e(TAG, "A general error occurred.");
                        }
                        callback.onResponse(sb.toString());
                    }
                });

        SafetyNet.getClient(ctx)
                .enableVerifyApps()
                .addOnCompleteListener(new OnCompleteListener<SafetyNetApi.VerifyAppsUserResponse>() {
                    @Override
                    public void onComplete(Task<SafetyNetApi.VerifyAppsUserResponse> task) {
                        if (task.isSuccessful()) {
                            SafetyNetApi.VerifyAppsUserResponse result = task.getResult();
                            if (result.isVerifyAppsEnabled()) {
                                sb.append("The user gave consent to enable the Verify Apps feature.\n");
                            } else {
                                sb.append("The user didn't give consent to enable the Verify Apps feature.\n");
                            }
                        } else {
                            sb.append("A general error occurred.\n");
                            Log.e(TAG, "A general error occurred.");
                        }
                        callback.onResponse(sb.toString());
                    }
                });

        SafetyNet.getClient(ctx)
                .listHarmfulApps()
                .addOnCompleteListener(new OnCompleteListener<SafetyNetApi.HarmfulAppsResponse>() {
                    @Override
                    public void onComplete(Task<SafetyNetApi.HarmfulAppsResponse> task) {
                        sb.append("Received listHarmfulApps() result\n");

                        if (task.isSuccessful()) {
                            SafetyNetApi.HarmfulAppsResponse result = task.getResult();
                            long scanTimeMs = result.getLastScanTimeMs();
                            List<HarmfulAppsData> appList = result.getHarmfulAppsList();
                            if (appList.isEmpty()) {
                                sb.append("There are no known potentially harmful apps installed.\n");
                            } else {
                                sb.append("Potentially harmful apps are installed!\n");

                                for (HarmfulAppsData harmfulApp : appList) {
                                    Log.e(TAG, "Information about a harmful app:");
                                    sb.append("Information about a harmful app:\n");
                                    Log.e(TAG,
                                            "  APK: " + harmfulApp.apkPackageName);
                                    sb.append("  APK: " + harmfulApp.apkPackageName + "\n");
                                    Log.e(TAG,
                                            "  SHA-256: " + harmfulApp.apkSha256);
                                    sb.append("  SHA-256: " + harmfulApp.apkSha256 + "\n");

                                    // Categories are defined in VerifyAppsConstants.
                                    Log.e(TAG,
                                            "  Category: " + harmfulApp.apkCategory);
                                    sb.append("  Category: " + harmfulApp.apkCategory + "\n");
                                }
                            }
                        } else {
                            sb.append("An error occurred. Call isVerifyAppsEnabled() to ensure that the user has consented.\n");
                            Log.d(TAG, "An error occurred. Call isVerifyAppsEnabled() to ensure that the user has consented.");
                        }
                        callback.onResponse(sb.toString());
                    }
                });
    }


    public void attestationNew() {
        String nonceData = "Safety Net Sample: " + System.currentTimeMillis();
        byte[] nonce = getRequestNonce(nonceData);// Should be at least 16 bytes in length.
        callback.onResponse(Base64.encodeToString(nonce, Base64.DEFAULT));

        SafetyNetClient client = SafetyNet.getClient(ctx);
        Log.d(TAG, BuildConfig.API_KEY);
        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, BuildConfig.API_KEY);
        task.addOnSuccessListener(mSuccessListener).addOnFailureListener(mFailureListener);
    }

    public void attestation() {
        String nonceData = "Safety Net Sample: " + System.currentTimeMillis();
        byte[] nonce = getRequestNonce(nonceData); // Should be at least 16 bytes in length.
        SafetyNet.SafetyNetApi.attest(googleApiClient, nonce)
                .setResultCallback(new ResultCallback<SafetyNetApi.AttestationResult>() {
                    @Override
                    public void onResult(SafetyNetApi.AttestationResult result) {
                        Status status = result.getStatus();
                        if (status.isSuccess()) {
                            // Indicates communication with the service was successful.
                            // result.getJwsResult() contains the result data
                            String mResult = status.getStatusMessage();
                            Log.d(TAG, "Success! SafetyNet result:\n" + mResult);
                            callback.onResponse("Success! SafetyNet result:\n" + mResult + "\n");
                        } else {
                            // An error occurred while communicating with the service
                            String mResult = status.getStatusMessage();
                            Log.e(TAG, "Fail SafetyNet result:\n" + mResult);
                        }
                    }
                });
    }

    /**
     * Called after successfully communicating with the SafetyNet API.
     * The #onSuccess callback receives an
     * {@link com.google.android.gms.safetynet.SafetyNetApi.AttestationResponse} that contains a
     * JwsResult with the attestation result.
     */
    private OnSuccessListener<SafetyNetApi.AttestationResponse> mSuccessListener =
            new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                @Override
                public void onSuccess(SafetyNetApi.AttestationResponse attestationResponse) {
                    /*
                     Successfully communicated with SafetyNet API.
                     Use result.getJwsResult() to get the signed result data. See the server
                     component of this sample for details on how to verify and parse this result.
                     */
                    String mResult = attestationResponse.getJwsResult();
                    Log.d(TAG, "Success! SafetyNet result:\n" + mResult + "\n");
                    callback.onResponse("Success! SafetyNet result:\n" + mResult + "\n");
                        /*
                         TODO(developer): Forward this result to your server together with
                         the nonce for verification.
                         You can also parse the JwsResult locally to confirm that the API
                         returned a response by checking for an 'error' field first and before
                         retrying the request with an exponential backoff.
                         NOTE: Do NOT rely on a local, client-side only check for security, you
                         must verify the response on a remote server!
                        */
                }
            };

    /**
     * Called when an error occurred when communicating with the SafetyNet API.
     */
    private OnFailureListener mFailureListener = new OnFailureListener() {
        @Override
        public void onFailure(@NonNull Exception e) {
            // An error occurred while communicating with the service.
            if (e instanceof ApiException) {
                // An error with the Google Play Services API contains some additional details.
                ApiException apiException = (ApiException) e;
                Log.e(TAG, "Error: " +
                        CommonStatusCodes.getStatusCodeString(apiException.getStatusCode()) + ": " +
                        apiException.getStatusMessage());
            } else {
                // A different, unknown type of error occurred.
                Log.e(TAG, "ERROR! " + e.getMessage());
            }

        }
    };


    private final Random mRandom = new SecureRandom();

    /**
     * Generates a 16-byte nonce with additional data.
     * The nonce should also include additional information, such as a user id or any other details
     * you wish to bind to this attestation. Here you can provide a String that is included in the
     * nonce after 24 random bytes. During verification, extract this data again and check it
     * against the request that was made with this nonce.
     */
    private byte[] getRequestNonce(String data) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[24];
        mRandom.nextBytes(bytes);
        try {
            byteStream.write(bytes);
            byteStream.write(data.getBytes());
        } catch (IOException e) {
            return null;
        }

        return byteStream.toByteArray();
    }

    private GoogleApiClient.ConnectionCallbacks googleApiConnectionCallbacks = new GoogleApiClient.ConnectionCallbacks() {
        @Override
        public void onConnected(@Nullable Bundle bundle) {
            String logs = bundle == null ? "" : bundle.toString();
            callback.onResponse("GoogleApiClient onConnected " + logs);
        }

        @Override
        public void onConnectionSuspended(int i) {
            Log.d(TAG, "onConnectionSuspended" + i);
        }
    };

    private GoogleApiClient.OnConnectionFailedListener googleApiConnectionFailedListener = new GoogleApiClient.OnConnectionFailedListener() {
        @Override
        public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
            Log.e(TAG, "onConnectionFailed:" + connectionResult.toString());

        }
    };
}
