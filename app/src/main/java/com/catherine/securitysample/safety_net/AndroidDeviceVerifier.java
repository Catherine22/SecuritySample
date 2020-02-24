package com.catherine.securitysample.safety_net;

import android.content.Context;

/**
 * Created by Catherine on 2017/7/3.

 */

public class AndroidDeviceVerifier {

    private final String jws;
    private Context ctx;

    public AndroidDeviceVerifier(Context ctx, String jws) {
        this.ctx = ctx;
        this.jws = jws;
    }

    public void verify(AttestationTaskCallback callback) {
        AttestationAsyncTask task = new AttestationAsyncTask(ctx, false, callback);
        task.execute(jws);
    }
}