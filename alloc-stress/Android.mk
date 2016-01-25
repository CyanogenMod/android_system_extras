LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := alloc-stress
LOCAL_CFLAGS += -g -Wall -Werror -std=gnu++11 -Wno-missing-field-initializers -Wno-sign-compare
ifneq ($(ENABLE_MEM_CGROUPS),)
    LOCAL_CFLAGS += -DENABLE_MEM_CGROUPS
endif
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_SHARED_LIBRARIES := libhardware libcutils
LOCAL_SRC_FILES := \
    alloc-stress.cpp
include $(BUILD_EXECUTABLE)
