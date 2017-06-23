LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := keys
LOCAL_SRC_FILES := Config.h
LOCAL_SRC_FILES := Config.cpp

include $(BUILD_SHARED_LIBRARY)