#
# Copyright (C) 2023 Xiaomi Corporation
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

include $(APPDIR)/Make.defs

CFLAGS += ${INCDIR_PREFIX}include
ifeq ($(CONFIG_OPTEE_COMPAT_MITEE_FS),y)
CFLAGS += ${INCDIR_PREFIX}include/mitee_compat
endif
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/optee/optee_os/optee_os/core/include
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/optee/optee_os/optee_os/ldelf/include
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/optee/optee_os/optee_os/lib/libutils/ext/include
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/optee/optee_os/optee_os/lib/libutee/include
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/library

ifeq ($(CONFIG_ARCH_ARM64),y)
CFLAGS += -DARM64
else ifeq ($(CONFIG_ARCH_ARM),y)
CFLAGS += -DARM32
else ifeq ($(CONFIG_ARCH_SIM),y)
CFLAGS += -DARM32
endif

CFLAGS += -DCFG_CORE_DYN_SHM
CFLAGS += -DCFG_NUM_THREADS=1
CFLAGS += -DCFG_OTP_SUPPORT
CFLAGS += -DCFG_OTP_SUPPORT_NO_PROVISION_TMP
CFLAGS += -DCFG_WITH_USER_TA

ifneq ($(CONFIG_DEBUG_INFO),)
CFLAGS += -DTRACE_LEVEL=3
else ifneq ($(CONFIG_DEBUG_WARN),)
CFLAGS += -DTRACE_LEVEL=2
else ifneq ($(CONFIG_DEBUG_ERROR),)
CFLAGS += -DTRACE_LEVEL=1
else
# the default TRACE_LEVEL are 1(with error level)
CFLAGS += -DTRACE_LEVEL=1
endif

ifeq ($(CONFIG_TEE_CORE_DEBUG),y)
CFLAGS += -DCFG_TEE_CORE_DEBUG
CSRCS += compat/spin_lock_debug.c
endif

CFG_HOST_FS_PARENT_PATH ?= $(CONFIG_OPTEE_HOST_FS_PARENT_PATH)
CFLAGS += -DHOST_FS_PARENT_PATH=\"$(CFG_HOST_FS_PARENT_PATH)\"

CSRCS += compat/abort.c
CSRCS += compat/atomic.c
CSRCS += compat/core_mmu.c
CSRCS += compat/hmac_memory.c
CSRCS += compat/host_fs.c
CSRCS += compat/ldelf_loader.c
CSRCS += compat/malloc.c
CSRCS += compat/mempool.c
CSRCS += compat/mobj.c
CSRCS += compat/mobj_dyn_shm.c
CSRCS += compat/msg_param.c
CSRCS += compat/notif.c
CSRCS += compat/otp_stubs.c
CSRCS += compat/panic.c
CSRCS += compat/random.c
CSRCS += compat/scall.c
CSRCS += compat/spinlock.c
CSRCS += compat/tee_time_system.c
CSRCS += compat/thread.c
CSRCS += compat/thread_optee_compat.c
CSRCS += compat/trace_ext.c
CSRCS += compat/ts_manager.c
CSRCS += compat/user_access.c
CSRCS += compat/user_mode_ctx.c
CSRCS += compat/vm.c

ifneq ($(CONFIG_OPTEE_RPMB_FS),)
CSRCS += compat/rpmb_fs.c
endif

ifeq ($(CONFIG_OPTEE_COMPAT_MITEE_FS),y)
CFLAGS += -DFS_STORAGE_DIR_PRIVATE=\"/sst/\"

CSRCS += compat/mitee_compat/huk_subkey.c
CSRCS += compat/mitee_compat/mitee_crypt.c
CSRCS += compat/mitee_compat/tee_fs_rpc.c
CSRCS += compat/mitee_compat/tee_fs_key_manager_compat.c
CSRCS += compat/mitee_compat/tee_obj.c
CSRCS += compat/mitee_compat/tee_ree_fs.c
CSRCS += compat/mitee_compat/tee_svc_compat.c
CSRCS += compat/mitee_compat/tee_svc_storage.c
endif

ifeq ($(strip $(CONFIG_USER_TA_WASM)),y)
CFLAGS += -DUSER_TA_WASM

CSRCS += wasm/user_ta_wasm.c
CSRCS += wasm/libtee_builtin_wrapper.c
endif

ifeq ($(CONFIG_OPTEE_SERVER_NONE),)
PROGNAME = $(CONFIG_OPTEE_SERVER_PROGNAME)
PRIORITY = $(CONFIG_OPTEE_SERVER_PRIORITY)
STACKSIZE = $(CONFIG_OPTEE_SERVER_STACKSIZE)
MAINSRC = server/opteed.c
endif

ASRCS := $(wildcard $(ASRCS))
CSRCS := $(wildcard $(CSRCS))
CXXSRCS := $(wildcard $(CXXSRCS))
MAINSRC := $(wildcard $(MAINSRC))
NOEXPORTSRCS = $(ASRCS)$(CSRCS)$(CXXSRCS)$(MAINSRC)

ifneq ($(NOEXPORTSRCS),)
BIN := $(APPDIR)/staging/liboptee$(LIBEXT)
endif

include $(APPDIR)/Application.mk
