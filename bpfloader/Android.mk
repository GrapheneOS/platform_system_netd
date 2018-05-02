LOCAL_PATH:= $(call my-dir)

#######################################
# bpf_kern.o
include $(CLEAR_VARS)

LOCAL_MODULE := bpf_kern.o
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf

include $(BUILD_PREBUILT)
