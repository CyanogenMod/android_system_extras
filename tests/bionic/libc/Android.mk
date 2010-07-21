# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build control file for Bionic's test programs
# define the BIONIC_TESTS environment variable to build the test programs
#
ifdef BIONIC_TESTS

LOCAL_PATH:= $(call my-dir)

# used to define a simple test program and build it as a standalone
# device executable.
#
# you can use EXTRA_CFLAGS to indicate additional CFLAGS to use
# in the build. the variable will be cleaned on exit
#
define device-test
  $(foreach file,$(1), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.c=%))) \
    $(eval LOCAL_MODULE := $(LOCAL_MODULE:%.cpp=%)) \
    $(eval LOCAL_CFLAGS += $(EXTRA_CFLAGS)) \
    $(eval LOCAL_LDFLAGS += $(EXTRA_LDLIBS)) \
    $(eval LOCAL_MODULE_TAGS := tests) \
    $(eval include $(BUILD_EXECUTABLE)) \
  ) \
  $(eval EXTRA_CFLAGS :=) \
  $(eval EXTRA_LDLIBS :=)
endef

# same as 'device-test' but builds a host executable instead
# you can use EXTRA_LDLIBS to indicate additional linker flags
#
define host-test
  $(foreach file,$(1), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.c=%))) \
    $(eval LOCAL_MODULE := $(LOCAL_MODULE:%.cpp=%)) \
    $(eval LOCAL_CFLAGS += $(EXTRA_CFLAGS)) \
    $(eval LOCAL_LDLIBS += $(EXTRA_LDLIBS)) \
    $(eval LOCAL_MODULE_TAGS := tests) \
    $(eval include $(BUILD_HOST_EXECUTABLE)) \
  ) \
  $(eval EXTRA_CFLAGS :=) \
  $(eval EXTRA_LDLIBS :=)
endef

# First, the tests in 'common'

sources := \
    common/test_getaddrinfo.c \
    common/test_gethostbyname.c \
    common/test_gethostname.c \
    common/test_pthread_cleanup_push.c \
    common/test_pthread_getcpuclockid.c \
    common/test_pthread_join.c \
    common/test_pthread_mutex.c \
    common/test_pthread_once.c \
    common/test_semaphore.c \
    common/test_sem_post.c \
    common/test_seteuid.c \
    common/test_static_cpp_mutex.cpp \
    common/test_strftime_2039.c \
    common/test_tm_zone.c \
    common/test_udp.c \

# _XOPEN_SOURCE=600 is needed to get pthread_mutexattr_settype() on GLibc
#
EXTRA_LDLIBS := -lpthread -lrt
EXTRA_CFLAGS := -D_XOPEN_SOURCE=600 -DHOST
$(call host-test, $(sources))
$(call device-test, $(sources))

# The 'test_dlopen_null' tests requires specific linker flags
#
# The -Wl,--export-dynamic ensures that dynamic symbols are
# exported from the executable.
#
# -Wl,-u,foo is used to ensure that symbol "foo" is not
# garbage-collected by the gold linker, since the function
# appears to be unused.
#
sources := common/test_dlopen_null.c \

EXTRA_LDLIBS := -ldl -Wl,--export-dynamic -Wl,-u,foo
EXTRA_CFLAGS := -DHOST
$(call host-test, $(sources))

EXTRA_LDLIBS := -ldl -Wl,--export-dynamic -Wl,-u,foo
$(call device-test, $(sources))


sources := \
    common/test_libgen.c \

EXTRA_CFLAGS := -DHOST
$(call host-test, $(sources))
$(call device-test, $(sources))

# Second, the Bionic-specific tests

sources :=  \
    bionic/test_mutex.c \
    bionic/test_cond.c \
    bionic/test_getgrouplist.c \
    bionic/test_netinet_icmp.c \
    bionic/test_pthread_cond.c \
    bionic/test_pthread_create.c \

$(call device-test, $(sources))

# Third, the other tests

sources := \
    other/bench_locks.c \
    other/test_aligned.c \
    other/test_arc4random.c \
    other/test_atomics.c \
    other/test_sysconf.c \
    other/test_system.c \
    other/test_thread_max.c \
    other/test_timer_create.c \
    other/test_timer_create2.c \
    other/test_timer_create3.c \
    other/test_vfprintf_leak.c \

$(call device-test, $(sources))

# The relocations test is a bit special, since we need
# to build one shared object and one executable that depends
# on it.

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/lib_relocs.c
LOCAL_MODULE    := libtest_relocs
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/test_relocs.c
LOCAL_MODULE    := test_relocs
LOCAL_SHARED_LIBRARIES := libtest_relocs
include $(BUILD_EXECUTABLE)

# This test tries to see if the static constructors in a
# shared library are only called once. We thus need to
# build a shared library, then call it from another
# program.
#
include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/lib_static_init.cpp
LOCAL_MODULE    := libtest_static_init
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/test_static_init.cpp
LOCAL_MODULE    := test_static_init
LOCAL_SHARED_LIBRARIES := libtest_static_init
include $(BUILD_EXECUTABLE)

# This test tries to see if static destructors are called
# on dlclose(). We thus need to generate a C++ shared library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/libdlclosetest1.cpp
LOCAL_MODULE := libdlclosetest1
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bionic/test_dlclose_destruction.c
LOCAL_MODULE := test_dlclose_destruction
LOCAL_LDFLAGS := -ldl
#LOCAL_SHARED_LIBRARIES := libdlclosetest1
include $(BUILD_EXECUTABLE)

# Testing 'clone' is only possible on Linux systems
include $(CLEAR_VARS)
LOCAL_SRC_FILES := common/test_clone.c
LOCAL_MODULE := test_clone
include $(BUILD_EXECUTABLE)

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := common/test_clone.c
LOCAL_MODULE := test_clone
include $(BUILD_HOST_EXECUTABLE)
endif

# TODO: Add a variety of GLibc test programs too...

# Hello World to test libstdc++ support

sources := \
    common/hello_world.cpp \

EXTRA_CFLAGS := -mandroid
#$(call device-test, $(sources))

endif  # BIONIC_TESTS
