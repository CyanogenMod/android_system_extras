# Copyright 2013 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	taskstats.c

LOCAL_C_INCLUDES := \
	external/libnl-headers

LOCAL_STATIC_LIBRARIES := \
	libnl_2

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE:= taskstats

include $(BUILD_EXECUTABLE)
