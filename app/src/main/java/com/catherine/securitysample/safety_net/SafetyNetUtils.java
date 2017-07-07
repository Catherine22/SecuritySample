package com.catherine.securitysample.safety_net;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import com.catherine.securitysample.Utils;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.safetynet.HarmfulAppsData;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;

import org.json.JSONException;

import java.security.SecureRandom;
import java.util.List;

/**
 * Created by Catherine on 2017/6/29.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public class SafetyNetUtils {
    private final static String TAG = "SafetyNetUtils";
    private Context ctx;
    private Callback callback;
    private final SecureRandom secureRandom;
    private GoogleApiClient googleApiClient;

    public SafetyNetUtils(Context ctx, @Nullable String API_KEY, Callback callback) {
        this.ctx = ctx;
        this.callback = callback;
        googleApiClient = new GoogleApiClient.Builder(ctx)
                .addApi(SafetyNet.API)
                .addConnectionCallbacks(googleApiConnectionCallbacks)
                .addOnConnectionFailedListener(googleApiConnectionFailedListener)
                .build();
        googleApiClient.connect();
        secureRandom = new SecureRandom();
    }

    public interface Callback {
        void onResponse(String message);

        void onFail(ErrorMessage code, String message);
    }

    public void verifyApps() {
        if (!isGooglePlayServicesAvailable()) return;

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

    public void requestAttestation(final boolean verifyJWSResponse) {
        if (!isGooglePlayServicesAvailable()) return;
        Log.d(TAG, String.format("ApkCertificateDigests:%s", Utils.calcApkCertificateDigests(ctx, ctx.getPackageName())));
        Log.d(TAG, String.format("ApkDigest:%s", Utils.calcApkDigest(ctx)));
        Log.v(TAG, "running SafetyNet.API Test");
        byte[] requestNonce = generateOneTimeRequestNonce();
        Log.d(TAG, "Nonce:" + Base64.encodeToString(requestNonce, Base64.DEFAULT));
        SafetyNet.SafetyNetApi.attest(googleApiClient, requestNonce)
                .setResultCallback(new ResultCallback<SafetyNetApi.AttestationResult>() {

                    @Override
                    public void onResult(@NonNull SafetyNetApi.AttestationResult attestationResult) {
                        Status status = attestationResult.getStatus();
                        boolean isSuccess = status.isSuccess();
                        if (!isSuccess)
                            callback.onFail(ErrorMessage.SAFETY_NET_API_NOT_WORK, ErrorMessage.SAFETY_NET_API_NOT_WORK.name());
                        else {
                            try {
                                final String jwsResult = attestationResult.getJwsResult();
                                final JwsHelper jwsHelper = new JwsHelper(jwsResult);
                                final AttestationResult response = new AttestationResult(jwsHelper.getDecodedPayload());
                                if (!verifyJWSResponse) {
                                    callback.onResponse(response.getFormattedString());
                                } else {
                                    try {
                                        Thread.sleep(500);
                                    } catch (InterruptedException e) {
                                        e.printStackTrace();
                                    }
                                    AndroidDeviceVerifier androidDeviceVerifier = new AndroidDeviceVerifier(ctx, jwsResult);
                                    androidDeviceVerifier.verify(new AttestationTaskCallback() {
                                        @Override
                                        public void error(String errorMsg) {
                                            callback.onFail(ErrorMessage.FAILED_TO_CALL_GOOGLE_API_SERVICES, errorMsg);
                                        }

                                        @Override
                                        public void success(boolean isValidSignature) {
                                            if (isValidSignature)
                                                callback.onResponse("isValidSignature true\n\n" + response.getFormattedString());
                                            else
                                                callback.onFail(ErrorMessage.ERROR_VALID_SIGNATURE, ErrorMessage.ERROR_VALID_SIGNATURE.name());
                                        }
                                    });
                                }
                            } catch (JSONException e) {
                                callback.onFail(ErrorMessage.EXCEPTION, e.getMessage());
                            }
                        }
                    }
                });
    }

    private boolean isGooglePlayServicesAvailable() {
        if (ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(ctx)) {
            Log.e(TAG, "GooglePlayServices is not available on this device.\n\nAttestation is not available.");
            callback.onFail(ErrorMessage.GOOGLE_PLAY_SERVICES_UNAVAILABLE, "GooglePlayServices is not available on this device.\n\nAttestation is not available.");
            return false;
        } else
            return true;
    }

    private byte[] generateOneTimeRequestNonce() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return nonce;
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
