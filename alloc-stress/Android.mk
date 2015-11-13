LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := alloc-stress
LOCAL_CFLAGS += -g -Wall -Werror -std=gnu++11 -Wno-missing-field-initializers -Wno-sign-compare
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_SHARED_LIBRARIES := libhardware
LOCAL_SRC_FILES := \
    alloc-stress.cpp
include $(BUILD_EXECUTABLE)
