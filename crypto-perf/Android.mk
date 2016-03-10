LOCAL_PATH := $(call my-dir)
ifeq ($(TARGET_ARCH),arm64)
include $(CLEAR_VARS)

LOCAL_CFLAGS := -O0 -march=armv8-a+crypto
LOCAL_SRC_FILES := crypto.cpp

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := crypto

include $(BUILD_EXECUTABLE)
endif
