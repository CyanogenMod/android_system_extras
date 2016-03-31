LOCAL_PATH:= $(call my-dir)

ifeq ($(HOST_OS),linux)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_MODULE := fec_test_read
LOCAL_SRC_FILES := test_read.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := \
    libfec_host \
    libfec_rs_host \
    libcrypto_utils_static \
    libcrypto_static \
    libext4_utils_host \
    libsquashfs_utils_host \
    libbase
LOCAL_CFLAGS := -Wall -Werror -D_GNU_SOURCE
include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_MODULE := fec_test_rs
LOCAL_SRC_FILES := test_rs.c
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libfec_rs_host
LOCAL_CFLAGS := -Wall -Werror -D_GNU_SOURCE
LOCAL_C_INCLUDES += external/fec
include $(BUILD_HOST_EXECUTABLE)

endif # HOST_OS == linux
