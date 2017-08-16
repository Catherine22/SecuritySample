package com.catherine.securitysample;

import android.app.Application;
import android.os.HandlerThread;

/**
 * Created by Catherine on 2017/8/16.
 */

public class MyApplication extends Application {
    public HandlerThread safetyNetLooper;
    public static MyApplication INSTANCE;

    @Override
    public void onCreate() {
        INSTANCE = this;
        safetyNetLooper = new HandlerThread("SafetyNet task");
        safetyNetLooper.start();
        super.onCreate();
    }
}
