package com.catherine.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends Activity implements SafetyNetUtils.Callback {
    private ListView lv_features;
    private TextView tv;
    private SafetyNetUtils snu;
    private SafetyNetHelper safetyNetHelper;
    private final String[] titles = {"Get encrypted data via NDK", "Verify apps", "Attestation"};
    private final static String TAG = "MainActivity";
    private final static String MODULUS = "AKfszhN0I/O12wcJ+r4wX0Im//5+pGeSFCXo4jOH18khVsspwgDaZgUJRxYIeK87kDOmk8U1j01Rsx2UFlThMjfwT9oliR1K/QihIujN7dgLSnBHh8wWXBI+P+hZq01uF2qrvWZQ+t2JySVBh7DO9uXxdjHrOLou97w3pjZzU4zn";
    private final static String EXPONENT = "AQAB";

    static {
        //relate to LOCAL_MODULE in Android.mk
        System.loadLibrary("keys");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        snu = new SafetyNetUtils(MainActivity.this, MainActivity.this);
        safetyNetHelper = new SafetyNetHelper(BuildConfig.API_KEY, MainActivity.this);
        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());
        if (ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)) {
            Log.e(TAG, "GooglePlayServices is not available on this device.\n\nThis SafetyNet test will not work");
            tv.setText("GooglePlayServices is not available on this device.\n\nThis SafetyNet test will not work");
        }
        lv_features.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final StringBuilder sb = new StringBuilder();
                switch (position) {
                    case 0:
                        try {
                            // Example of a call to a native method

                            String[] authChain = getAuthChain("LOGIN");
                            sb.append("Decrypted secret keys\n[ ");
                            for (int i = 0; i < authChain.length; i++) {
                                sb.append(decryptRSA(authChain[i]));
                                sb.append(" ");
                            }
                            sb.append("]\n");

                            String[] authChain2 = getAuthChain("OTHER");
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
//                        snu.attestationNew();
                        safetyNetHelper.requestTest(MainActivity.this, new SafetyNetHelper.SafetyNetWrapperCallback() {
                            @Override
                            public void error(int errorCode, String errorMessage) {
                                Log.d(TAG, errorCode + ":" + errorMessage);
                            }

                            @Override
                            public void success(boolean ctsProfileMatch, boolean basicIntegrity) {
                                Log.d(TAG, "SafetyNet req success: ctsProfileMatch:" + ctsProfileMatch + " and basicIntegrity, " + basicIntegrity);
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        tv.setText(safetyNetHelper.getLastResponse().toString());
                                    }
                                });
                            }
                        });
                        break;
                }
            }
        });

    }


    private void initView() {
        tv = (TextView) findViewById(R.id.sample_text);
        lv_features = (ListView) findViewById(R.id.lv_features);
        lv_features.setAdapter(new ArrayAdapter<>(MainActivity.this, R.layout.activity_main_item, R.id.tv_title, titles));
    }

    /**
     * Decrypt messages by RSA algorithm<br>
     *
     * @param message
     * @return Original message
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException
     */
    public static String decryptRSA(String message) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException {
        Cipher c2 = Cipher.getInstance(Algorithm.rules.get("RSA")); // 创建一个Cipher对象，注意这里用的算法需要和Key的算法匹配

        BigInteger m = new BigInteger(Base64.decode(MODULUS.getBytes(), Base64.DEFAULT));
        BigInteger e = new BigInteger(Base64.decode(EXPONENT.getBytes(), Base64.DEFAULT));
        c2.init(Cipher.DECRYPT_MODE, convertStringToPublicKey(m, e)); // 设置Cipher为解密工作模式，需要把Key传进去
        byte[] decryptedData = c2.doFinal(Base64.decode(message.getBytes(), Base64.DEFAULT));
        return new String(decryptedData, Algorithm.CHARSET);
    }

    /**
     * You can component a publicKey by a specific pair of values - modulus and
     * exponent.
     *
     * @param modulus  When you generate a new RSA KeyPair, you'd get a PrivateKey, a
     *                 modulus and an exponent.
     * @param exponent When you generate a new RSA KeyPair, you'd get a PrivateKey, a
     *                 modulus and an exponent.
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static Key convertStringToPublicKey(BigInteger modulus, BigInteger exponent)
            throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] modulusByteArry = modulus.toByteArray();
        byte[] exponentByteArry = exponent.toByteArray();

        // 由接收到的参数构造RSAPublicKeySpec对象
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(modulusByteArry),
                new BigInteger(exponentByteArry));
        // 根据RSAPublicKeySpec对象获取公钥对象
        KeyFactory kFactory = KeyFactory.getInstance(Algorithm.KEYPAIR_ALGORITHM);
        PublicKey publicKey = kFactory.generatePublic(rsaPublicKeySpec);
        // System.out.println("==>public key: " +
        // bytesToHexString(publicKey.getEncoded()));
        return publicKey;
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String[] getAuthChain(String key);


    @Override
    public void onResponse(String message) {
        tv.setText(message);
    }
}
