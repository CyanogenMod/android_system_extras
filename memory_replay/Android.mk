LOCAL_PATH := $(call my-dir)

memory_replay_src_files := \
	Action.cpp \
	LineBuffer.cpp \
	NativeInfo.cpp \
	Pointers.cpp \
	Thread.cpp \
	Threads.cpp \

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(memory_replay_src_files) main.cpp
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := memory_replay
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(memory_replay_src_files) main.cpp
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := memory_replay
LOCAL_MODULE_HOST_OS := linux
LOCAL_LDLIBS := -lrt
include $(BUILD_HOST_EXECUTABLE)

memory_replay_test_src_files := \
	tests/ActionTest.cpp \
	tests/LineBufferTest.cpp \
	tests/NativeInfoTest.cpp \
	tests/PointersTest.cpp \
	tests/ThreadTest.cpp \
	tests/ThreadsTest.cpp \

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	$(memory_replay_src_files) \
	$(memory_replay_test_src_files) \

LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_C_INCLUDES := $(LOCAL_PATH)/tests
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := memory_replay_tests

LOCAL_SHARED_LIBRARIES := libbase

LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	$(memory_replay_src_files) \
	$(memory_replay_test_src_files) \

LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_C_INCLUDES := $(LOCAL_PATH)/tests
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := memory_replay_tests
LOCAL_MODULE_HOST_OS := linux

LOCAL_SHARED_LIBRARIES := libbase
LOCAL_LDLIBS := -lrt

LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_HOST_NATIVE_TEST)

memory_replay_src_files :=
memory_replay_test_src_files :=
