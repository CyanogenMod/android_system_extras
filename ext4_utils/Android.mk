# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

ifneq ($(wildcard $(ANDROID_BUILD_TOP)/external/lz4/Android.mk),)
LOCAL_HAVE_LZ4 := true
endif

libext4_utils_src_files := \
    make_ext4fs.c \
    ext4fixup.c \
    ext4_utils.c \
    allocate.c \
    contents.c \
    extent.c \
    indirect.c \
    uuid.c \
    sha1.c \
    wipe.c \
    crc16.c \
    ext4_sb.c \
    canned_fs_config.c

#
# -- All host/targets including windows
#

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils_host
LOCAL_STATIC_LIBRARIES := \
    libsparse_host \
    libz

ifneq ($(HOST_OS),windows)
  LOCAL_STATIC_LIBRARIES += libselinux
endif

ifeq ($(LOCAL_HAVE_LZ4),true)
LOCAL_CFLAGS += -DHAVE_LZ4
LOCAL_C_INCLUDES += external/lz4/lib
LOCAL_STATIC_LIBRARIES += liblz4-host
endif

include $(BUILD_HOST_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := make_ext4fs_main.c
LOCAL_MODULE := make_ext4fs
LOCAL_STATIC_LIBRARIES += \
    libext4_utils_host \
    libsparse_host \
    libz
ifeq ($(HOST_OS),windows)
  LOCAL_LDLIBS += -lws2_32
else
  LOCAL_STATIC_LIBRARIES += libselinux
  LOCAL_CFLAGS := -DHOST
endif
ifeq ($(LOCAL_HAVE_LZ4),true)
LOCAL_CFLAGS += -DHAVE_LZ4
LOCAL_C_INCLUDES += external/lz4/lib
LOCAL_STATIC_LIBRARIES += liblz4-host
endif
include $(BUILD_HOST_EXECUTABLE)


#
# -- All host/targets excluding windows
#

ifneq ($(HOST_OS),windows)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_C_INCLUDES += external/zlib
LOCAL_MODULE := libext4_utils
LOCAL_SHARED_LIBRARIES := \
    libselinux \
    libsparse \
    libz
ifeq ($(LOCAL_HAVE_LZ4),true)
LOCAL_CFLAGS += -DHAVE_LZ4
LOCAL_C_INCLUDES += external/lz4/lib
LOCAL_STATIC_LIBRARIES += liblz4-static
endif
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_C_INCLUDES += external/zlib
LOCAL_MODULE := libext4_utils_static
LOCAL_STATIC_LIBRARIES += \
    libselinux \
    libsparse_static
ifeq ($(LOCAL_HAVE_LZ4),true)
LOCAL_CFLAGS += -DHAVE_LZ4
LOCAL_C_INCLUDES += external/lz4/lib
endif
include $(BUILD_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := make_ext4fs_main.c
LOCAL_MODULE := make_ext4fs
LOCAL_SHARED_LIBRARIES := \
    libext4_utils \
    libselinux \
    libz
ifeq ($(LOCAL_HAVE_LZ4),true)
LOCAL_CFLAGS += -DHAVE_LZ4
LOCAL_C_INCLUDES += external/lz4/lib
LOCAL_STATIC_LIBRARIES += liblz4-static
endif
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := ext2simg.c
LOCAL_MODULE := ext2simg
LOCAL_SHARED_LIBRARIES += \
    libext4_utils \
    libselinux \
    libsparse \
    libz
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := ext2simg.c
LOCAL_MODULE := ext2simg
LOCAL_STATIC_LIBRARIES += \
    libext4_utils_host \
    libselinux \
    libsparse_host \
    libz
include $(BUILD_HOST_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := setup_fs.c
LOCAL_MODULE := setup_fs
LOCAL_SHARED_LIBRARIES += libcutils
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := ext4fixup_main.c
LOCAL_MODULE := ext4fixup
LOCAL_SHARED_LIBRARIES += \
    libext4_utils \
    libsparse \
    libz
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES := ext4fixup_main.c
LOCAL_MODULE := ext4fixup
LOCAL_STATIC_LIBRARIES += \
    libext4_utils_host \
    libsparse_host \
    libz
include $(BUILD_HOST_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_MODULE := mkuserimg.sh
LOCAL_SRC_FILES := mkuserimg.sh
LOCAL_MODULE_CLASS := EXECUTABLES
# We don't need any additional suffix.
LOCAL_MODULE_SUFFIX :=
LOCAL_BUILT_MODULE_STEM := $(notdir $(LOCAL_SRC_FILES))
LOCAL_IS_HOST_MODULE := true
include $(BUILD_PREBUILT)

endif

