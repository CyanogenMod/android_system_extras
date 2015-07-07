LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= ANRdaemon.cpp

LOCAL_C_INCLUDES += external/zlib

LOCAL_MODULE:= anrdaemon

LOCAL_MODULE_TAGS:= optional

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libcutils \
    libutils \
    libz \

include $(BUILD_EXECUTABLE)
