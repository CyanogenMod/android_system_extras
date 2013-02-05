# Copyright 2013 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := opentest.c
LOCAL_MODULE := opentest
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

