# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

libext4_utils_src_files := \
        make_ext4fs.c \
        ext4fixup.c \
        ext4_utils.c \
        allocate.c \
        backed_block.c \
        output_file.c \
        contents.c \
        extent.c \
        indirect.c \
        uuid.c \
        sha1.c \
        sparse_crc32.c \
        wipe.c

# -- All host/targets including windows

LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += external/zlib

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_STATIC_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := make_ext4fs_main.c
LOCAL_MODULE := make_ext4fs
LOCAL_STATIC_LIBRARIES += libext4_utils libz
ifeq ($(HOST_OS),windows)
LOCAL_LDLIBS += -lws2_32
else
ifeq ($(HAVE_SELINUX), true)
LOCAL_STATIC_LIBRARIES += libselinux
endif # HAVE_SELINUX
endif

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

# -- All host/targets excluding windows

ifneq ($(HOST_OS),windows)

LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += external/zlib
LOCAL_SHARED_LIBRARIES := libz

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_SHARED_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(libext4_utils_src_files)
LOCAL_MODULE := libext4_utils
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += external/zlib

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_STATIC_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := make_ext4fs_main.c
LOCAL_MODULE := make_ext4fs
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libext4_utils libz

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_SHARED_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ext2simg.c
LOCAL_MODULE := ext2simg
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libext4_utils libz

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_SHARED_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ext2simg.c
LOCAL_MODULE := ext2simg
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libext4_utils libz

ifeq ($(HAVE_SELINUX), true)
LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_STATIC_LIBRARIES += libselinux
LOCAL_CFLAGS += -DHAVE_SELINUX
endif # HAVE_SELINUX

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := simg2img.c \
	sparse_crc32.c
LOCAL_MODULE := simg2img
LOCAL_MODULE_TAGS := debug

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := simg2img.c \
	sparse_crc32.c
LOCAL_MODULE := simg2img
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := img2simg.c
LOCAL_MODULE := img2simg
LOCAL_MODULE_TAGS := debug

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := img2simg.c
LOCAL_MODULE := img2simg
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := setup_fs.c
LOCAL_MODULE := setup_fs
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libcutils
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ext4fixup_main.c
LOCAL_MODULE := ext4fixup
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libext4_utils libz

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ext4fixup_main.c
LOCAL_MODULE := ext4fixup
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES += libext4_utils libz

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

include $(CLEAR_VARS)

LOCAL_MODULE := simg_dump.py
LOCAL_MODULE_TAGS := debug
LOCAL_SRC_FILES := simg_dump.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true

include $(BUILD_PREBUILT)

endif
