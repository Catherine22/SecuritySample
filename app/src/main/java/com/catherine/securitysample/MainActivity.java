package com.catherine.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

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
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends Activity implements GoogleApiClient.ConnectionCallbacks {
    private ListView lv_features;
    private TextView tv;
    private GoogleApiClient googleApiClient;
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
        initComponent();
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
                        SafetyNet.getClient(MainActivity.this)
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
                                        tv.setText(sb.toString());
                                    }
                                });

                        SafetyNet.getClient(MainActivity.this)
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
                                        tv.setText(sb.toString());
                                    }
                                });

                        SafetyNet.getClient(MainActivity.this)
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
                                        tv.setText(sb.toString());
                                    }
                                });

                        break;
                    case 2:
                        String nonceData = "Safety Net Sample: " + System.currentTimeMillis();
                        byte[] nonce = getRequestNonce(nonceData);// Should be at least 16 bytes in length.
                        tv.setText(Base64.encodeToString(nonce, Base64.DEFAULT));
                        SafetyNetClient client = SafetyNet.getClient(MainActivity.this);
                        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, getString(R.string.ATTEST_API_KEY));
                        task.addOnSuccessListener(MainActivity.this, mSuccessListener).addOnFailureListener(MainActivity.this, mFailureListener);

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

    private void initComponent() {
        googleApiClient = new GoogleApiClient.Builder(this)
                .addApi(SafetyNet.API)
                .addConnectionCallbacks(MainActivity.this)
                .build();
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

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String[] getAuthChain(String key);

    @Override
    public void onConnected(@Nullable Bundle bundle) {
        String logs = bundle == null ? "" : bundle.toString();
        Log.d(TAG, "onConnected " + logs);
    }

    @Override
    public void onConnectionSuspended(int i) {
        Log.d(TAG, "onConnectionSuspended" + i);
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
                    tv.setText("Success! SafetyNet result:\n" + mResult + "\n");
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
}
