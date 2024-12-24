// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/readdir.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/compat.h>

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/moduleparam.h>


#include "linux/cred.h"

static int filter_from_user_apps = 0;
module_param(filter_from_user_apps, int, 0640);
//MODULE_PARM_DESC(filter_from_user_apps, "filter_from_user_apps");

static int filter_debug_all = 0;
module_param(filter_debug_all, int, 0640);
//MODULE_PARM_DESC(filter_debug_all, "filter_debug_all");

static int filter_debug_user = 0;
module_param(filter_debug_user, int, 0640);
//MODULE_PARM_DESC(filter_debug_all, "filter_debug_all");

static int filter_debug_uid = -1;
module_param(filter_debug_uid, int, 0640);
//MODULE_PARM_DESC(filter_debug_all, "filter_debug_all");

static int filter_invert = 0;
module_param(filter_invert, int, 0640);
//MODULE_PARM_DESC(filter_debug_all, "filter_debug_all");

static int filter_uids[2048];
static int filter_uids_count;
module_param_array(filter_uids, int, &filter_uids_count, 0640);

static inline uid_t get_cur_uid(void) {
    return __kuid_val(current_uid());
}

static inline bool is_root_uid(void) {
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}


static inline bool is_filtered_uid(uid_t uid) {
    int i;
    for(i=0;i<filter_uids_count;i++) {
        if( filter_uids[i] == uid ) return !filter_invert;
    }
    return filter_invert;
}

static void print_debug(const char *name) {

    uid_t uid = get_cur_uid();

    if( filter_debug_all != 0 || 
        (filter_debug_user != 0 && uid >= 10000 ) ||
        filter_debug_uid == uid ) {
        pr_info("filter_out name=%s (%d)", name, uid);
    }
}

const char *bl_list_eq[] = {
    "addon.d",
    ".TWRP",
    "TWRP",
    "su",
    "magisk",
    ".ext",
    "/system/addon.d",
    "/metadata/magisk/zygisk_lsposed",
    "/system/framework/XposedBridge.jar",
    /*"/system/bin/su",
    "/system/xbin/su",
    "/system/bin/.ext/su",
    "/system/xbin/.ext/su",
    "/data/local/xbin/su",
    "/data/local/tmp/su",
    "/data/local/bin/su",
    "/sbin/su",
    "/product/bin/su",
    "/system_ext/bin/su",
    "/odm/bin/su",
    "/vendor/bin/su",
    "/vendor/xbin/su",
    "/product/bin/magisk",
    "/apex/com.android.runtime/bin/su",
    "/apex/com.android.runtime/bin/magisk",
    "/apex/com.android.art/bin/su",
    "/apex/com.android.art/bin/magisk",
    "/system_ext/bin/magisk",
    "/system/bin/magisk",
    "/system/xbin/magisk",
    "/odm/bin/magisk",
    "/vendor/bin/magisk",
    "/vendor/xbin/magisk",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/data/local/su",
    "/su/bin/su",*/
    NULL
};

static int strends(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int filter_out(const char *name) {
    int res = 0;

    print_debug(name);

    if( !filter_from_user_apps || is_root_uid() || !is_filtered_uid(get_cur_uid()) ) return 0;

    if( strends(name,"/su") != 0 ) res = -EPERM;
    if( strends(name,"/busybox") != 0 ) res = -EPERM;
    if( strstr(name,"zygisk") != NULL ) res = -EPERM;
    if( strstr(name,"magisk") != NULL ) res = -EPERM;

    int i;
    if( res != 0 ) {
        for( i=0;;i++ ) { 
            if( !bl_list_eq[i] ) break;
            if( !strcmp(bl_list_eq[i], name) ) {
                res = -EPERM;
                break;
            }
        }
    }

    if (res) {
        pr_info("filter_out blocked name=%s (%d)", name, get_cur_uid());
        return res;
    }

    return 0;
}

