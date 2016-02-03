LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := sound
LOCAL_SRC_FILES := playwav.c
LOCAL_CFLAGS := -Wno-unused-parameter
include $(BUILD_EXECUTABLE)

