LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tcp_nuke_addr_test

LOCAL_C_INCLUDES += frameworks/native/include external/libcxx/include
LOCAL_CPPFLAGS += -std=c++11 -Wall -Werror
LOCAL_SHARED_LIBRARIES := libc++
LOCAL_SRC_FILES := tcp_nuke_addr_test.cpp
LOCAL_MODULE_TAGS := eng tests

include $(BUILD_NATIVE_TEST)
