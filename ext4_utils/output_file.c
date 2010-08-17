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
#include "sparse_format.h"
#include "sparse_crc32.h"

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define off64_t off_t
#endif

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_MINOR_VER 0
#define SPARSE_HEADER_LEN       (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

struct output_file_ops {
	int (*seek)(struct output_file *, off64_t);
	int (*write)(struct output_file *, u8 *, int);
	void (*close)(struct output_file *);
};

struct output_file {
	int fd;
	gzFile gz_fd;
	int sparse;
	u64 cur_out_ptr;
	int chunk_cnt;
	u32 crc32;
	struct output_file_ops *ops;
};

static int file_seek(struct output_file *out, off64_t off)
{
	off64_t ret;

	ret = lseek64(out->fd, off, SEEK_SET);
	if (ret < 0) {
		error_errno("lseek64");
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

static int gz_file_seek(struct output_file *out, off64_t off)
{
	off64_t ret;

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

static sparse_header_t sparse_header = {
	.magic = SPARSE_HEADER_MAGIC,
	.major_version = SPARSE_HEADER_MAJOR_VER,
	.minor_version = SPARSE_HEADER_MINOR_VER,
	.file_hdr_sz = SPARSE_HEADER_LEN,
	.chunk_hdr_sz = CHUNK_HEADER_LEN,
	.blk_sz = 0,
	.total_blks = 0,
	.total_chunks = 0,
	.image_checksum = 0
};

static u8 *zero_buf;

static int emit_skip_chunk(struct output_file *out, u64 skip_len)
{
	chunk_header_t chunk_header;
	int ret, chunk;

	//DBG printf("skip chunk: 0x%llx bytes\n", skip_len);

	if (skip_len % info.block_size) {
		error("don't care size %llu is not a multiple of the block size %u",
				skip_len, info.block_size);
		return -1;
	}

	/* We are skipping data, so emit a don't care chunk. */
	chunk_header.chunk_type = CHUNK_TYPE_DONT_CARE;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = skip_len / info.block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN;
	ret = out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));
	if (ret < 0)
		return -1;

	out->cur_out_ptr += skip_len;
	out->chunk_cnt++;

	/* Compute the CRC for all those zeroes.  Do it block_size bytes at a time. */
	while (skip_len) {
		chunk = (skip_len > info.block_size) ? info.block_size : skip_len;
		out->crc32 = sparse_crc32(out->crc32, zero_buf, chunk);
		skip_len -= chunk;
	}

	return 0;
}

static int write_chunk_raw(struct output_file *out, u64 off, u8 *data, int len)
{
	chunk_header_t chunk_header;
	int rnd_up_len, zero_len;
	int ret;

	/* We can assume that all the chunks to be written are in
	 * ascending order, block-size aligned, and non-overlapping.
	 * So, if the offset is less than the current output pointer,
	 * throw an error, and if there is a gap, emit a "don't care"
	 * chunk.  The first write (of the super block) may not be
	 * blocksize aligned, so we need to deal with that too.
	 */
	//DBG printf("write chunk: offset 0x%llx, length 0x%x bytes\n", off, len);

	if (off < out->cur_out_ptr) {
		error("offset %llu is less than the current output offset %llu",
				off, out->cur_out_ptr);
		return -1;
	}

	if (off > out->cur_out_ptr) {
		emit_skip_chunk(out, off - out->cur_out_ptr);
	}

	if (off % info.block_size) {
		error("write chunk offset %llu is not a multiple of the block size %u",
				off, info.block_size);
		return -1;
	}

	if (off != out->cur_out_ptr) {
		error("internal error, offset accounting screwy in write_chunk_raw()");
		return -1;
	}

	/* Round up the file length to a multiple of the block size */
	rnd_up_len = (len + (info.block_size - 1)) & (~(info.block_size -1));
	zero_len = rnd_up_len - len;

	/* Finally we can safely emit a chunk of data */
	chunk_header.chunk_type = CHUNK_TYPE_RAW;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = rnd_up_len / info.block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN + rnd_up_len;
	ret = out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));

	if (ret < 0)
		return -1;
	ret = out->ops->write(out, data, len);
	if (ret < 0)
		return -1;
	if (zero_len) {
		ret = out->ops->write(out, zero_buf, zero_len);
		if (ret < 0)
			return -1;
	}

	out->crc32 = sparse_crc32(out->crc32, data, len);
	if (zero_len)
		out->crc32 = sparse_crc32(out->crc32, zero_buf, zero_len);
	out->cur_out_ptr += rnd_up_len;
	out->chunk_cnt++;

	return 0;
}

void close_output_file(struct output_file *out)
{
	int ret;

	if (out->sparse) {
		/* we need to seek back to the beginning and update the file header */
		sparse_header.total_chunks = out->chunk_cnt;
		sparse_header.image_checksum = out->crc32;

		ret = out->ops->seek(out, 0);
		if (ret < 0)
			error("failure seeking to start of sparse file");

		ret = out->ops->write(out, (u8 *)&sparse_header, sizeof(sparse_header));
		if (ret < 0)
			error("failure updating sparse file header");
	}
	out->ops->close(out);
}

struct output_file *open_output_file(const char *filename, int gz, int sparse)
{
	int ret;
	struct output_file *out = malloc(sizeof(struct output_file));
	if (!out) {
		error_errno("malloc struct out");
		return NULL;
	}
	zero_buf = malloc(info.block_size);
	if (!zero_buf) {
		error_errno("malloc zero_buf");
		return NULL;
	}
	memset(zero_buf, '\0', info.block_size);

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
	out->sparse = sparse;
	out->cur_out_ptr = 0ll;
	out->chunk_cnt = 0;

	/* Initialize the crc32 value */
	out->crc32 = 0;

	if (out->sparse) {
		/* Write out the file header.  We'll update the unknown fields
		 * when we close the file.
		 */
		sparse_header.blk_sz = info.block_size,
		sparse_header.total_blks = info.len / info.block_size,
		ret = out->ops->write(out, (u8 *)&sparse_header, sizeof(sparse_header));
		if (ret < 0)
			return NULL;
	}

	return out;
}

void pad_output_file(struct output_file *out, u64 len)
{
	int ret;

	if (len > info.len) {
		error("attempted to pad file %llu bytes past end of filesystem",
				len - info.len);
		return;
	}
	if (out->sparse) {
		/* We need to emit a DONT_CARE chunk to pad out the file if the
		 * cur_out_ptr is not already at the end of the filesystem.
		 * We also need to compute the CRC for it.
		 */
		if (len < out->cur_out_ptr) {
			error("attempted to pad file %llu bytes less than the current output pointer",
					out->cur_out_ptr - len);
			return;
		}
		if (len > out->cur_out_ptr) {
			emit_skip_chunk(out, len - out->cur_out_ptr);
		}
	} else {
		//KEN TODO: Fixme.  If the filesystem image needs no padding,
		//          this will overwrite the last byte in the file with 0
		//          The answer is to do accounting like the sparse image
		//          code does and know if there is already data there.
		ret = out->ops->seek(out, len - 1);
		if (ret < 0)
			return;

		ret = out->ops->write(out, (u8*)"", 1);
		if (ret < 0)
			return;
	}
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

	if (out->sparse) {
		write_chunk_raw(out, off, data, len);
	} else {
		ret = out->ops->seek(out, off);
		if (ret < 0)
			return;

		ret = out->ops->write(out, data, len);
		if (ret < 0)
			return;
	}
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

	if (out->sparse) {
		write_chunk_raw(out, off, data, len);
	} else {
		ret = out->ops->seek(out, off);
		if (ret < 0)
			goto err;

		ret = out->ops->write(out, data, len);
		if (ret < 0)
			goto err;
	}

	munmap(data, len);

	close(file_fd);

err:
	munmap(data, len);
	close(file_fd);
}

