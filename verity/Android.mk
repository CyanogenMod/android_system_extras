LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := generate_verity_key
LOCAL_SRC_FILES := generate_verity_key.c
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcrypto-host
LOCAL_C_INCLUDES += external/openssl/include
include $(BUILD_HOST_EXECUTABLE)

#include $(CLEAR_VARS)
#LOCAL_MODULE := generate_block_patch
#LOCAL_SRC_FILES := generate_block_patch.c
#LOCAL_MODULE_CLASS := EXECUTABLES
#LOCAL_MODULE_TAGS := optional
#LOCAL_SHARED_LIBRARIES := libminibsdiff
#include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := VeritySigner.java
LOCAL_MODULE := VeritySigner
LOCAL_JAR_MANIFEST := VeritySigner.mf
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := verity_signer
LOCAL_MODULE := verity_signer
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := build_verity_tree.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := build_verity_tree.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := build_verity_metadata.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := build_verity_metadata.py
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)
