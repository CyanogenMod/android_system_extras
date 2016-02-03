LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	refresh.c

LOCAL_SHARED_LIBRARIES := \
	libcutils

LOCAL_MODULE:= test-fb-refresh

LOCAL_CFLAGS := -Wno-unused-parameter

include $(BUILD_EXECUTABLE)

##

include $(CLEAR_VARS)
LOCAL_SRC_FILES := fb_test.c
LOCAL_MODULE = test-fb-simple
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc
LOCAL_CFLAGS := -Wno-unused-parameter
include $(BUILD_EXECUTABLE)
