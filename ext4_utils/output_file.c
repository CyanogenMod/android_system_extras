/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <zlib.h>

#include "ext4_utils.h"
#include "output_file.h"

struct output_file_ops {
	int (*seek)(struct output_file *, off_t);
	int (*write)(struct output_file *, u8 *, int);
	void (*close)(struct output_file *);
};

struct output_file {
	int fd;
	gzFile gz_fd;
	struct output_file_ops *ops;
};

static int file_seek(struct output_file *out, off_t off)
{
	off_t ret;

	ret = lseek(out->fd, off, SEEK_SET);
	if (ret < 0) {
		error_errno("lseek");
		return -1;
	}
	return 0;
}

static int file_write(struct output_file *out, u8 *data, int len)
{
	int ret;
	ret = write(out->fd, data, len);
	if (ret < 0) {
		error_errno("write");
		return -1;
	} else if (ret < len) {
		error("incomplete write");
		return -1;
	}

	return 0;
}

static void file_close(struct output_file *out)
{
	close(out->fd);
}


static struct output_file_ops file_ops = {
	.seek = file_seek,
	.write = file_write,
	.close = file_close,
};

static int gz_file_seek(struct output_file *out, off_t off)
{
	off_t ret;

	ret = gzseek(out->gz_fd, off, SEEK_SET);
	if (ret < 0) {
		error_errno("gzseek");
		return -1;
	}
	return 0;
}

static int gz_file_write(struct output_file *out, u8 *data, int len)
{
	int ret;
	ret = gzwrite(out->gz_fd, data, len);
	if (ret < 0) {
		error_errno("gzwrite");
		return -1;
	} else if (ret < len) {
		error("incomplete gzwrite");
		return -1;
	}

	return 0;
}

static void gz_file_close(struct output_file *out)
{
	gzclose(out->gz_fd);
}

static struct output_file_ops gz_file_ops = {
	.seek = gz_file_seek,
	.write = gz_file_write,
	.close = gz_file_close,
};

void close_output_file(struct output_file *out)
{
	out->ops->close(out);
}

struct output_file *open_output_file(const char *filename, int gz)
{
	struct output_file *out = malloc(sizeof(struct output_file));
	if (!out) {
		error_errno("malloc");
		return NULL;
	}

	if (gz) {
		out->ops = &gz_file_ops;
		out->gz_fd = gzopen(filename, "wb9");
		if (!out->gz_fd) {
			error_errno("gzopen");
			free(out);
			return NULL;
		}
	} else {
		out->ops = &file_ops;
		out->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (out->fd < 0) {
			error_errno("open");
			free(out);
			return NULL;
		}
	}
	return out;
}

/* Write a contiguous region of data blocks from a memory buffer */
void write_data_block(struct output_file *out, u64 off, u8 *data, int len)
{
	int ret;
	
	if (off + len > info.len) {
		error("attempted to write block %llu past end of filesystem",
				off + len - info.len);
		return;
	}

	ret = out->ops->seek(out, off);
	if (ret < 0)
		return;

	ret = out->ops->write(out, data, len);
	if (ret < 0)
		return;
}

/* Write a contiguous region of data blocks from a file */
void write_data_file(struct output_file *out, u64 off, const char *file,
		     off_t offset, int len)
{
	int ret;

	if (off + len >= info.len) {
		error("attempted to write block %llu past end of filesystem",
				off + len - info.len);
		return;
	}

	int file_fd = open(file, O_RDONLY);
	if (file_fd < 0) {
		error_errno("open");
		return;
	}

	u8 *data = mmap(NULL, len, PROT_READ, MAP_SHARED, file_fd, offset);
	if (data == MAP_FAILED) {
		error_errno("mmap");
		close(file_fd);
		return;
	}

	ret = out->ops->seek(out, off);
	if (ret < 0)
		goto err;

	ret = out->ops->write(out, data, len);
	if (ret < 0)
		goto err;


	munmap(data, len);

	close(file_fd);

err:
	munmap(data, len);
	close(file_fd);
}
