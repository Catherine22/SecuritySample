package com.catherine.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.catherine.securitysample.SafetyNet.SafetyNetHelper;
import com.catherine.securitysample.SafetyNet.SafetyNetResponse;
import com.catherine.securitysample.SafetyNet.SafetyNetUtils;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;

import java.text.SimpleDateFormat;
import java.util.Locale;

public class MainActivity extends Activity implements SafetyNetUtils.Callback {
    private final String[] titles = {"Get encrypted data via NDK", "Verify apps", "Attestation"};
    private final static String TAG = "MainActivity";
    private ListView lv_features;
    private TextView tv;
    private JNIHelper jniHelper;
    private SafetyNetUtils snu;
    private SafetyNetHelper safetyNetHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        initComponent();
        lv_features.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final StringBuilder sb = new StringBuilder();
                switch (position) {
                    case 0:
                        try {
                            // Example of a call to a native method
                            String[] authChain = jniHelper.getAuthChain("LOGIN");
                            sb.append("Decrypted secret keys\n[ ");
                            for (int i = 0; i < authChain.length; i++) {
                                sb.append(JNIHelper.decryptRSA(authChain[i]));
                                sb.append(" ");
                            }
                            sb.append("]\n");

                            String[] authChain2 = jniHelper.getAuthChain("OTHER");
                            sb.append("secret keys\n[ ");
                            for (int i = 0; i < authChain.length; i++) {
                                sb.append(authChain2[i]);
                                sb.append(" ");
                            }
                            sb.append("]");
                            Log.d(TAG, sb.toString());
                            tv.setText(sb.toString());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    case 1:
                        snu.verifyAppsNew();
                        break;
                    case 2:
                        safetyNetHelper.requestTest(MainActivity.this, new SafetyNetHelper.SafetyNetWrapperCallback() {
                            @Override
                            public void error(int errorCode, String errorMessage) {
                                Log.d(TAG, errorCode + ":" + errorMessage);
                                tv.setText(format(safetyNetHelper.getLastResponse()));
                            }

                            @Override
                            public void success(boolean ctsProfileMatch, boolean basicIntegrity) {
                                Log.d(TAG, "SafetyNet req success: ctsProfileMatch:" + ctsProfileMatch + " and basicIntegrity, " + basicIntegrity);

                                tv.setText(format(safetyNetHelper.getLastResponse()));
                            }
                        });
                        break;
                }
            }
        });

    }

    private void initComponent() {
        snu = new SafetyNetUtils(MainActivity.this, MainActivity.this);
        safetyNetHelper = new SafetyNetHelper(BuildConfig.API_KEY);
        jniHelper = new JNIHelper();
        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());
        if (ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)) {
            Log.e(TAG, "GooglePlayServices is not available on this device.\n\nThis SafetyNet test will not work");
            tv.setText("GooglePlayServices is not available on this device.\n\nThis SafetyNet test will not work");
        }
    }

    private String format(SafetyNetResponse r) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (String s : r.getApkCertificateDigestSha256()) {
            sb.append(s);
            sb.append(", ");
        }
        sb.delete(sb.length() - 2, sb.length());
        sb.append("]");
        SimpleDateFormat newFormat = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss", Locale.TAIWAN);
        String formattedTime = newFormat.format(r.getTimestampMs());
        return String.format("Request Time:\n%s\n\nNonce:\n%s\n\nPackageName:\n%s\n\nApkCertificateDigestSha256:\n%s\n\nApkDigestSha256:\n%s\n\nctsProfileMatch:\n%s\n\nbasicIntegrity:\n%s", formattedTime, r.getNonce(), r.getApkPackageName(), sb.toString(), r.getApkDigestSha256(), r.isCtsProfileMatch(), r.isBasicIntegrity());
    }


    private void initView() {
        tv = (TextView) findViewById(R.id.sample_text);
        lv_features = (ListView) findViewById(R.id.lv_features);
        lv_features.setAdapter(new ArrayAdapter<>(MainActivity.this, R.layout.activity_main_item, R.id.tv_title, titles));
    }


    @Override
    public void onResponse(String message) {
        tv.setText(message);
    }
}
