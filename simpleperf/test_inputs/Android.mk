
# some data files used by simpleperf_unit_test

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := fibonacci.jar
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA_NATIVE_TESTS)/simpleperf_unit_test
LOCAL_SRC_FILES := fibonacci.jar
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := has_embedded_native_libs.apk
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA_NATIVE_TESTS)/simpleperf_unit_test
LOCAL_SRC_FILES := has_embedded_native_libs.apk
include $(BUILD_PREBUILT)
