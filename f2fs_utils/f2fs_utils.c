/*
 * Copyright (C) 2014 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _LARGEFILE64_SOURCE

#include <fcntl.h>
#include <string.h>

#include <f2fs_fs.h>
#include <f2fs_format_utils.h>

#include <sparse/sparse.h>

struct selabel_handle;

#include "make_f2fs.h"

extern void flush_sparse_buffs();
extern void init_sparse_file(unsigned int block_size, int64_t len);
extern void finalize_sparse_file(int fd);

extern struct f2fs_configuration *f2fs_config;
extern int dlopenf2fs();

static void reset_f2fs_info() {
	memset(f2fs_config, 0, sizeof(*f2fs_config));
	f2fs_config->fd = -1;
	f2fs_config->kd = -1;
}

int make_f2fs_sparse_fd(int fd, long long len,
		const char *mountpoint, struct selabel_handle *sehnd)
{
	if (dlopenf2fs() < 0) {
		return -1;
	}
	reset_f2fs_info();
	f2fs_init_configuration(f2fs_config);
	len &= ~((__u64)F2FS_BLKSIZE);
	f2fs_config->total_sectors = len / f2fs_config->sector_size;
	f2fs_config->start_sector = 0;
	init_sparse_file(F2FS_BLKSIZE, len);
	f2fs_format_device();
	finalize_sparse_file(fd);
	flush_sparse_buffs();
	return 0;
}
