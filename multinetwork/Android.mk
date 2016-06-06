LOCAL_PATH := $(call my-dir)

# The PDK build does not have access to frameworks/native elements.
ifneq ($(TARGET_BUILD_PDK), true)

# Sample util binaries.
include $(CLEAR_VARS)
LOCAL_MODULE := dnschk

LOCAL_C_INCLUDES += frameworks/native/include external/libcxx/include
LOCAL_CPPFLAGS += -std=c++11
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_SHARED_LIBRARIES := libandroid libbase libc++
LOCAL_SRC_FILES := dnschk.cpp common.cpp
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := httpurl

LOCAL_C_INCLUDES += frameworks/native/include external/libcxx/include
LOCAL_CPPFLAGS += -std=c++11
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_SHARED_LIBRARIES := libandroid libbase libc++
LOCAL_SRC_FILES := httpurl.cpp common.cpp
include $(BUILD_EXECUTABLE)

endif  # ifneq ($(TARGET_BUILD_PDK), true)
