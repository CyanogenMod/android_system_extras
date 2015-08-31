# Copyright 2015 The Android Open Source Project

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := bootctl.c
LOCAL_SHARED_LIBRARIES := libhardware
LOCAL_MODULE := bootctl
LOCAL_C_INCLUDES = hardware/libhardware/include
LOCAL_CFLAGS := -Wno-unused-parameter

include $(BUILD_EXECUTABLE)
