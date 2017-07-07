package com.catherine.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.catherine.securitysample.safety_net.ErrorMessage;
import com.catherine.securitysample.safety_net.SafetyNetUtils;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;


public class MainActivity extends Activity implements SafetyNetUtils.Callback {
    private final String[] titles = {"Get encrypted data via NDK", "Verify apps", "Attestation"};
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
                    case 1:
                        snu.verifyApps();
                        break;
                    case 2:
                        snu.requestAttestation(true);
                        break;
                }
            }
        });

    }

    private void initComponent() {
        snu = new SafetyNetUtils(MainActivity.this, BuildConfig.API_KEY, MainActivity.this);
        jniHelper = new JNIHelper();
        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());
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
        tv.setText("Error:" + message);
    }
}
