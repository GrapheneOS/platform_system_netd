#
# Copyright (C) 2016 The Android Open Source Project
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
#
# Note: netd benchmark can't build on nyc-mr2-dev, because google-benchmark project is out of date
#       and won't be backported, and thus the content of this file is commented out to disable it.
#       In order to run netd benchmark locally you can uncomment the content of this file and follow
#       instructions in ag/1673408 (checkout that commit and build external/google-benchmark and
#       system/netd locally and then run the benchmark locally)
#
#
#LOCAL_PATH := $(call my-dir)
#
## APCT build target for metrics tests
#include $(CLEAR_VARS)
#LOCAL_MODULE := netd_benchmark
#LOCAL_CFLAGS := -Wall -Werror -Wunused-parameter
## Bug: http://b/29823425 Disable -Wvarargs for Clang update to r271374
#LOCAL_CFLAGS += -Wno-varargs

#EXTRA_LDLIBS := -lpthread
#LOCAL_SHARED_LIBRARIES += libbase libbinder liblog libnetd_client
#LOCAL_STATIC_LIBRARIES += libnetd_test_dnsresponder libtestUtil libutils

#LOCAL_AIDL_INCLUDES := system/netd/server/binder
#LOCAL_C_INCLUDES += system/netd/include \
#                    system/extras/tests/include \
#                    system/netd/client \
#                    system/netd/server \
#                    system/netd/server/binder \
#                    system/netd/tests/dns_responder \
#                    system/extras/tests/include \
#                    bionic/libc/dns/include

#LOCAL_SRC_FILES := main.cpp \
#                   connect_benchmark.cpp \
#                   dns_benchmark.cpp \
#                   ../../server/binder/android/net/metrics/INetdEventListener.aidl

#LOCAL_MODULE_TAGS := eng tests

#include $(BUILD_NATIVE_BENCHMARK)
