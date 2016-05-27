ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := ANRdaemon.cpp
LOCAL_C_INCLUDES += external/zlib
LOCAL_MODULE := anrd
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libcutils \
    libutils \
    libz
include $(BUILD_EXECUTABLE)

endif
