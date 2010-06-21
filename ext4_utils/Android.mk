# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

libext4_utils_src_files := \
        ext4_utils.c \
        allocate.c \
        backed_block.c \
        output_file.c \
        contents.c \
        extent.c \
        indirect.c \
        uuid.c \
        sha1.c \

LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += external/zlib
LOCAL_SHARED_LIBRARIES := libz
LOCAL_PRELINK_MODULE := false

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libz

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := make_ext4fs.c
LOCAL_MODULE := make_ext4fs
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libext4_utils libz

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := make_ext4fs.c
LOCAL_MODULE := make_ext4fs
LOCAL_STATIC_LIBRARIES += libext4_utils libz

include $(BUILD_HOST_EXECUTABLE)
