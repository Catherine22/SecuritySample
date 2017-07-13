package com.catherine.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.catherine.securitysample.safety_net.ErrorMessage;
import com.catherine.securitysample.safety_net.SafetyNetUtils;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;


public class MainActivity extends Activity implements SafetyNetUtils.Callback {
    private final String[] titles = {"Show apk info", "Get encrypted data via NDK", "Verify apps", "Attestation"};
    private final static String TAG = "MainActivity";
    private ListView lv_features;
    private TextView tv;
    private JNIHelper jniHelper;
    private SafetyNetUtils snu;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        initComponent();
        lv_features.setOnItemClickListener((parent, view, position, id) -> {
            final StringBuilder sb = new StringBuilder();
            switch (position) {
                case 0:
                    sb.append(String.format("package name:%s\n", getPackageName()));
                    //This keypair stores in your keystore. You can also see the same information by "keytool -list -v -keystore xxx.keystore  -alias xxx  -storepass xxx -keypass xxx" command
                    sb.append(String.format("fingerprint:[\nMD5:%s\nSHA1:%s\nSHA256:%s\n]\n", Utils.getSigningKeyFingerprint(this, Algorithm.MD5), Utils.getSigningKeyFingerprint(this, Algorithm.SHA1), Utils.getSigningKeyFingerprint(this, Algorithm.SHA256)));

                    sb.append(String.format("apkCertificateDigestSha256:%s\n", Utils.calcApkCertificateDigests(MainActivity.this, MainActivity.this.getPackageName())));
                    sb.append(String.format("apkDigest:%s", Utils.calcApkDigest(MainActivity.this)));
                    Log.d(TAG, sb.toString());
                    tv.setText(sb.toString());
                    break;
                case 1:
                    try {
                        // Example of a call to a native method
                        String[] authChain = jniHelper.getAuthChain("LOGIN");
                        sb.append("Decrypted secret keys\n[ ");
                        for (int i = 0; i < authChain.length; i++) {
                            sb.append(jniHelper.decryptRSA(authChain[i]));
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
                case 2:
                    snu.verifyApps();
                    break;
                case 3:
                    snu.requestAttestation(true);
                    break;
            }
        });

    }

    private void initComponent() {
        snu = new SafetyNetUtils(MainActivity.this, MainActivity.this);
        jniHelper = new JNIHelper();
        if (ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)) {
            Log.e(TAG, "GooglePlayServices is not available on this device.\n\nAttestation is not available.");
            tv.setText("GooglePlayServices is not available on this device.\n\nAttestation is not available.");
        }
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

    @Override
    public void onFail(ErrorMessage errorMessage, String message) {
        tv.setText(String.format("Error:%s", message));
    }
}
