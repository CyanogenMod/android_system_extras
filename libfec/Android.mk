# Copyright 2015 The Android Open Source Project
#
LOCAL_PATH := $(call my-dir)

common_cflags := -Wall -Werror -O3

common_c_includes := \
    $(LOCAL_PATH)/include \
    external/fec \
    system/extras/ext4_utils \
    system/extras/squashfs_utils

common_src_files := \
    fec_open.cpp \
    fec_read.cpp \
    fec_verity.cpp \
    fec_process.cpp

common_static_libraries := \
    libmincrypt \
    libcrypto_static \
    libcutils \
    libbase

include $(CLEAR_VARS)
LOCAL_CFLAGS := $(common_cflags)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_MODULE := libfec
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_STATIC_LIBRARIES := \
    libfec_rs \
    libext4_utils_static \
    libsquashfs_utils \
    libcutils \
    $(common_static_libraries)
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CFLAGS := $(common_cflags) -D_GNU_SOURCE -DFEC_NO_KLOG
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CLANG := true
ifeq ($(HOST_OS),linux)
LOCAL_SANITIZE := integer
endif
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_MODULE := libfec_host
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_STATIC_LIBRARIES := \
    libfec_rs_host \
    libext4_utils_host \
    libsquashfs_utils_host \
    $(common_static_libraries)
include $(BUILD_HOST_STATIC_LIBRARY)

include $(LOCAL_PATH)/test/Android.mk
