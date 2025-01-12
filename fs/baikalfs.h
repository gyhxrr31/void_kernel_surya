/* fs/ internal definitions
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef BAIKALFS_H

#include <linux/fs.h>
#include <linux/mount.h>

extern int filter_out(const char *tag, const char *name);
extern int filter_out_path(const char *tag, const struct path* const file);
extern int filter_out_mount(const char *tag, struct vfsmount* const mnt, const struct path* const root);

#endif /* BAIKALFS_H */
