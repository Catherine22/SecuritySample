//
// Created by Catherine on 2017/6/15.
//
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include "Config.h"

extern "C" {
    #define TAGNAME "JNI_LOG"


    JNIEXPORT jobjectArray JNICALL
    Java_com_catherine_securitysample_MainActivity_getAuthChain(JNIEnv *env, jobject instance, jstring key) {

    jobjectArray valueArray = (jobjectArray)env->NewObjectArray(5, env->FindClass("java/lang/String"), 0);

    const char *keyChar = env->GetStringUTFChars(key, 0);

     if(strcmp(keyChar, "LOGIN") == 0){
     //通过RSA加密的字串，由于Key是随机生成的，一旦有新的字串加入，之前加密过的栏位也要一并重新加密，整个做一次替换，
     //同时还要更新解密端的modulus和exponent值（只适用RSA）
        const char *hash[5];
        hash[0] = "WwpuWNahzInOuuv/PDvqvkis5TVdqM+8vnncIM0weAAYsQfT8HOeElw0cz9QMKb8ZOXuagybcbutDFlkgFuVVzU/0Mm+GddK1N11U+R3YdEmKLWql17ivGAXsU4WUF+TMISlmVtV33e87pjH4XXd+/JyAoGQ3PuCh/XRo1r2CjM=";
        hash[1] = "SLwdSffpKfRM3Robb9s1k4+ES1tU02l5GvOuGc8CV2YmzPRci6TUqdNNyhjT0QfVWZYoqf1ziES0NAXYWJrDd+5E9ogIngMPR/wgXVOvlF82hqIS1HUIE1m9AWjxkf4JswuFst4IJOReeHUE8IdmpmsUyZ7ytyXCIyPBZtkQfkY=";
        hash[2] = "nF/osRti5KL7ODFObGDtmiKou1q0B5eB3fhkAybnPX/cRH/qCx/z4oLV71RRR2tAi5GPwdrmhqpIh2/2dC1CWvVljwWnpcu2PluV6smHQQne/kTFkg4oEb5ojdCpes8r7CSgjKFfiLGzV1+kG7Rm7rbLoNx0YCU/ZjHsoraezKA=";
        hash[3] = "M9J+3oMymFQ4Iy/j9LDTCMr43//zQrVAkbAn94u3O3TIzWvfGcRX+sd4Kw0hLWhADXX3ev1dxDEn9I3ZIZL06Ax/NqwrL2+6EcQcfxfDwfIQBfSnFoKX+Sl9S9N1ncp19tTggY/qqgJNQTAMPy22LMcktkKOcghPeWhT0RxVvMg=";
        hash[4] = "AT3ytwsWYD74oJz8FwvyhcrrM7/d/kGf3/Owd7q2SuHGPIyTC46uBP0OcX09Dhl9r60jW1lT6Rmyckja45hqX2rjXTsxfHpWL+KLBD7jrjTS9rfPOH7S2rP04ePxtBF9qkQmAEu5x39J/CD3dI+YtMUtZo3XCzbYUBdpHVuGP4Y=";
        for (int i=0; i<5; i++)
        {
            jstring value = env->NewStringUTF(hash[i]);
            env->SetObjectArrayElement(valueArray, i, value);
        }
     }else{
     //作为对照，这边放还没加密过原本的字串，实际应用时，只需要放加密过的字串就行了
        const char *hash[5];
        hash[0] = "Czc0SC";
        hash[1] = "xvaw089";
        hash[2] = "ca90vj";
        hash[3] = "NCV0dk";
        hash[4] = "Xhf0i4m";
        for (int i=0; i<5; i++)
        {
            jstring value = env->NewStringUTF(hash[i]);
            env->SetObjectArrayElement(valueArray, i, value);
         }
     }
        return valueArray;
    }
}