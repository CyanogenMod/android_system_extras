# Copyright 2015 The Android Open Source Project

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := boot_control_copy.c bootinfo.c
LOCAL_CFLAGS := -Wall -Wno-missing-field-initializers -Wno-unused-parameter
LOCAL_C_INCLUDES := system/core/mkbootimg bootable/recovery
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_STATIC_LIBRARIES := libfs_mgr

LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE:= bootctrl.default
include $(BUILD_SHARED_LIBRARY)
