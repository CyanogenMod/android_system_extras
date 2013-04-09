# Copyright 2013 The Android Open Source Project
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
# Add any strcmp or memcpy implementation files below.
LOCAL_SRC_FILES:= \
	main.cpp \

LOCAL_MODULE := libc_test
LOCAL_MODULE_TAGS := debug

ifeq ($(TARGET_ARCH),arm)
LOCAL_ASFLAGS := -mthumb
endif # arm

include $(BUILD_EXECUTABLE)
