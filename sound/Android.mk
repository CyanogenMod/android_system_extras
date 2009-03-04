LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := sound
LOCAL_SRC_FILES := playwav.c
LOCAL_MODULE_TAGS := tests
include $(BUILD_EXECUTABLE)

