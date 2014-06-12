# Copyright 2014 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

libf2fs_ioutils_src_files := \
    f2fs_ioutils.c

# ---------------------------------------
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(libf2fs_ioutils_src_files)
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
LOCAL_STATIC_LIBRARIES := \
    libsparse_host \
    libext2_uuid_host \
    libz
LOCAL_MODULE := libf2fs_ioutils_host
include $(BUILD_HOST_STATIC_LIBRARY)

# ---------------------------------------
include $(CLEAR_VARS)
LOCAL_SRC_FILES := f2fs_dlutils.c
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
# Will attempt to dlopen("libf2fs_fmt_host_dyn")
LOCAL_LDLIBS := -ldl
LOCAL_MODULE := libf2fs_dlutils_host
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libf2fs_utils_host
LOCAL_SRC_FILES := f2fs_utils.c
LOCAL_STATIC_LIBRARIES := \
    libsparse_host \
    libz
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
include $(BUILD_HOST_STATIC_LIBRARY)


#
# -- All host/targets excluding windows
#

ifneq ($(HOST_OS),windows)

include $(CLEAR_VARS)
LOCAL_MODULE := libf2fs_dlutils
LOCAL_SRC_FILES := f2fs_dlutils.c
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
LOCAL_SHARED_LIBRARIES := libdl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libf2fs_dlutils_static
LOCAL_SRC_FILES := f2fs_dlutils.c
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
LOCAL_SHARED_LIBRARIES := libdl
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libf2fs_utils_static
LOCAL_SRC_FILES := f2fs_utils.c
LOCAL_C_INCLUDES := external/f2fs-tools/include external/f2fs-tools/mkfs
LOCAL_STATIC_LIBRARIES := \
    libsparse_static
include $(BUILD_STATIC_LIBRARY)

endif

