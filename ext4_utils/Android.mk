# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

make_ext4fs_src_files := \
        make_ext4fs.c \
        ext_utils.c \
        allocate.c \
        backed_block.c \
        contents.c \
        extent.c \
        indirect.c \
        uuid.c \
        sha1.c \

LOCAL_SRC_FILES := $(make_ext4fs_src_files)
LOCAL_MODULE := make_ext4fs
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(make_ext4fs_src_files)
LOCAL_MODULE := make_ext4fs

include $(BUILD_HOST_EXECUTABLE)
