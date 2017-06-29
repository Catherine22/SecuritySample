package com.catherine.securitysample.SafetyNet;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.safetynet.HarmfulAppsData;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;

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
