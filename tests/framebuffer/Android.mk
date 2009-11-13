LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	refresh.c

LOCAL_SHARED_LIBRARIES := \
	libcutils

LOCAL_MODULE:= test-fb-refresh

LOCAL_MODULE_TAGS := optional

ifeq ($(TARGET_SIMULATOR),true)
  ifeq ($(HOST_OS),linux)
    # need this for clock_gettime()
    LOCAL_LDLIBS += -lrt
  endif
endif

include $(BUILD_EXECUTABLE)

##

ifneq ($(TARGET_SIMULATOR),true)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := fb_test.c
LOCAL_MODULE = test-fb-simple
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := mdp_test.c
LOCAL_MODULE = test-mdp
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc
include $(BUILD_EXECUTABLE)

endif # sim
