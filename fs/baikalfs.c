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
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/compat.h>

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/moduleparam.h>


#include "linux/cred.h"
#include "baikalfs.h"

static int filter_from_user_apps = 0;
module_param(filter_from_user_apps, int, 0640);

static int filter_debug_all = 0;
module_param(filter_debug_all, int, 0640);

static int filter_debug_user = 0;
module_param(filter_debug_user, int, 0640);

static int filter_debug_uid = -1;
module_param(filter_debug_uid, int, 0640);

static int filter_invert = 0;
module_param(filter_invert, int, 0640);

static int filter_isolated = 0;
module_param(filter_isolated, int, 0640);

static int filter_uids[2048];
static int filter_uids_count;
module_param_array(filter_uids, int, &filter_uids_count, 0640);




static inline uid_t get_cur_uid(void) {
    //return __kuid_val(current_uid());
	const struct cred* const credentials = current_cred();

	if (credentials == NULL) {
		return 0;
	}

	return credentials->uid.val;
}

static inline bool is_root_uid(void) {
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}


static inline bool is_filtered_uid(uid_t uid) {
    int i;

    if( uid < 10000 ) return 0;

    if( filter_isolated && uid >= 90000 ) return true;

    for(i=0;i<filter_uids_count;i++) {
        if( filter_uids[i] == uid ) return !filter_invert;
    }
    return filter_invert;
}

static void print_debug(const char *tag, const char *name) {

    uid_t uid = get_cur_uid();

    if( filter_debug_all != 0 || 
        (filter_debug_user != 0 && uid >= 10000 ) ||
        filter_debug_uid == uid ) {
        pr_info("filter_out from %s name=%s (%d)", tag, name, uid);
    }
}

static const char* bl_list_mount_types[] = {
	"overlay",
    NULL
};

static const char* bl_list_mounts[] = {
	"/data/adb",
	"/apex/com.android.art/bin/dex2oat",
	"/apex/com.android.art/bin/dex2oat32",
	"/apex/com.android.art/bin/dex2oat64",
	"/system/apex/com.android.art/bin/dex2oat",
	"/system/etc/preloaded-classes",
	"/dev/zygisk",
    "/sys/fs/pstore",
    "/dev/usb-ffs/adb",
    NULL
};

static const char *bl_list_ends[] = {
    "/su",
    "/daemonsu",
    "/adbd",
    "/supolicy",
    "/busybox",
    "/vboxuser",
    "/vboxguest",
    "/vboxsf-1",
    "/qemud",
    "/qemu_trace",
    "/qemu_pipe",
    "/rcvboxadd",
    "/bst_gps",
    "/bstfolderd",
    "/bstmods",
    "/noxd",
    "/noxspeedup",
    "/nox-prop",
    "/nox-vbox-sf",
    "/selinux",
    "/install-recovery.sh",
    "/libsupol.so",
    NULL
};

static const char *bl_list_contains[] = {
    "zygisk",
    "magisk",
    "system/addon.d",
    "com.noshufou.android.su",
    "supersu",
    "busybox",
    "xposed",
    "Xposed",
    NULL
};

static const char *bl_list_eq[] = {
    "/system/addon.d",
    "/data/adbroot",
    "/sys/fs/selinux/load",
    "/dev/socket/adbd",
    "/sdcard/TWRP",
    "/storage/emulated/0/TWRP",
    "addon.d",
    ".TWRP",
    "TWRP",
    "su",
    ".ext",
    NULL
};

static int strends(const char *str, const char *suffix)
{
    size_t lenstr = 0;
    size_t lensuffix = 0;
    if (!str || !suffix)
        return 0;
    lenstr = strlen(str);
    lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

static int check_list(const char *list[], const char *name, int type) {

    int res = 0;
    int i;
    for( i=0;;i++ ) { 
        if( !list[i] ) break;
        switch(type) {
            case 0:
                if( strstr(name, list[i] ) != NULL ) {
                    res = -EPERM;
                    break;
                }
            case 1:
                if( strends(name, list[i] ) != 0 ) {
                    res = -EPERM;
                    break;
                } 
             case 2:
                if( !strcmp(name, list[i]) ) {
                    res = -EPERM;
                    break;
                } 
        } 
        if( res ) return res;
    }
    return 0;
}

int filter_out_name(const char *tag, const char *name) {
    int res = 0;

    if( !res ) res = check_list(bl_list_contains, name, 0);
    if( !res ) res = check_list(bl_list_ends, name, 1);
    if( !res ) res = check_list(bl_list_eq, name, 2);

    if (res) {
        pr_info("filter_out blocked from %s name=%s (%d)", tag, name, get_cur_uid());
        return res;
    }

    return 0;
}

int filter_out(const char *tag, const char *name) {

    print_debug(tag, name);

    if( !filter_from_user_apps || is_root_uid() || !is_filtered_uid(get_cur_uid()) ) return 0;

    return filter_out_name(tag,name);
}

int filter_out_path(const char *tag, const struct path* const file) {
	size_t size = 4096;
	int res = 0;
    int len = -1;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;

    if( !filter_from_user_apps || is_root_uid() ) return 0;

    path = kmalloc(size, GFP_KERNEL);

	if (path == NULL) {
		res = -1;
		goto out;
	}

	ptr = d_path(file, path, size);

	if (IS_ERR(ptr)) {
		res = -1;
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		res = -1;
		goto out;
	}

	len = end - path;
	path[(size_t) len] = '\0';

    print_debug(tag, path);

    if( !is_filtered_uid(get_cur_uid()) ) goto out;

    res = filter_out_name(tag, path);
out:
    kfree(path);
    return res;
}

int filter_out_mount(const char *tag, struct vfsmount* const mnt, const struct path* const root) {
	size_t size = 4096;
	int res = 0;
	int len = -1;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;

	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt
	};

    if( !filter_from_user_apps || is_root_uid() ) return 0;

    path = kmalloc(size, GFP_KERNEL);

	if (path == NULL) {
		res = -1;
		goto out;
	}

	ptr = __d_path(&mnt_path, root, path, size);

	if (!ptr) {
		res = -1;
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		res = -1;
		goto out;
	}

	len = end - path;
	path[(size_t) len] = '\0';    

    print_debug(tag, path);

    if( !is_filtered_uid(get_cur_uid()) ) { 
        res = 0;
        goto out;
    }

    res = check_list(bl_list_mount_types,mnt->mnt_root->d_sb->s_type->name,2);
    if (res) {
        pr_info("filter_out_mount blocked from %s fs type name=%s (%d)", tag, mnt->mnt_root->d_sb->s_type->name, get_cur_uid());
        goto out;
    }

    res = check_list(bl_list_mounts,path,2);

    if (res) {
        pr_info("filter_out_mount blocked from %s name=%s (%d)", tag, path, get_cur_uid());
    }

out:
    kfree(path);
    return res;
}


