# Copyright 2006 The Android Open Source Project
ifneq ($(filter $(TARGET_ARCH),arm arm64),)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    memtest.cpp \
    fptest.cpp \
    thumb.cpp \
    bandwidth.cpp \

LOCAL_MODULE := memtest
LOCAL_MODULE_TAGS := debug
LOCAL_CFLAGS += \
    -fomit-frame-pointer \
    -Wall \
    -Werror \

LOCAL_MULTILIB := 32

LOCAL_SANITIZE := never

include $(BUILD_EXECUTABLE)
endif
