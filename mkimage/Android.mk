LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := mkimage.c crc32.c
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := mkimage

include $(BUILD_HOST_EXECUTABLE)
