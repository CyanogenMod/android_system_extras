#
# Copyright (C) 2015 The Android Open Source Project
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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE:= postinst_example
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := postinst.sh

# Create a symlink from /postinst to our default post-install script in the
# same filesystem as /postinst.
# TODO(deymo): Remove this symlink and add the path to the product config.
LOCAL_POST_INSTALL_CMD := \
    $(hide) ln -sf bin/postinst_example $(TARGET_OUT)/postinst
include $(BUILD_PREBUILT)
