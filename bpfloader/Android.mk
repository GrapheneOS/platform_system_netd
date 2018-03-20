LOCAL_PATH:= $(call my-dir)

#######################################
# bpf_ingress.o
include $(CLEAR_VARS)

LOCAL_MODULE := cgroup_bpf_ingress_prog.o
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf

include $(BUILD_PREBUILT)

#######################################
# bpf_egress.o
include $(CLEAR_VARS)

LOCAL_MODULE := cgroup_bpf_egress_prog.o
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf

include $(BUILD_PREBUILT)

#######################################
# xt_bpf_ingress_prog.o
include $(CLEAR_VARS)

LOCAL_MODULE := xt_bpf_ingress_prog.o
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf

include $(BUILD_PREBUILT)

#######################################
# xt_bpf_egress_prog.o
include $(CLEAR_VARS)

LOCAL_MODULE := xt_bpf_egress_prog.o
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf

include $(BUILD_PREBUILT)
