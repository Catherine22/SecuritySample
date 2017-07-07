package com.catherine.securitysample.safety_net;

/**
 * Created by Catherine on 2017/7/7.
 * Soft-World Inc.
 * catherine919@soft-world.com.tw
 */

public interface AttestationTaskCallback {
    void error(String s);

    void success(boolean isValidSignature);
}
