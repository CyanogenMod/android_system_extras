LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CLANG := true
ifeq ($(HOST_OS),linux)
LOCAL_SANITIZE := integer
endif
LOCAL_MODULE := fec
LOCAL_SRC_FILES := main.cpp image.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := \
    libsparse_host \
    libz \
    libcrypto_utils_static \
    libcrypto_static \
    libfec_host \
    libfec_rs_host \
    libext4_utils_host \
    libsquashfs_utils_host
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_CFLAGS += -Wall -Werror -O3
LOCAL_C_INCLUDES += external/fec
include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_MODULE := fec
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SRC_FILES := main.cpp image.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := \
    libcrypto_utils_static \
    libcrypto_static \
    libfec \
    libfec_rs \
    libbase \
    libext4_utils_static \
    libsquashfs_utils \
    libcutils
LOCAL_CFLAGS += -Wall -Werror -O3 -DIMAGE_NO_SPARSE=1
LOCAL_C_INCLUDES += external/fec
include $(BUILD_EXECUTABLE)
