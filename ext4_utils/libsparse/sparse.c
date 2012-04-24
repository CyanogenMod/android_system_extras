/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "output_file.h"
#include "backed_block.h"
#include "sparse_defs.h"

struct count_chunks {
	unsigned int chunks;
	off64_t cur_ptr;
	unsigned int block_size;
};

static void count_data_block(void *priv, off64_t off, void *data, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static void count_fill_block(void *priv, off64_t off, unsigned int fill_val, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static void count_file_block(void *priv, off64_t off, const char *file,
		off64_t offset, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static int count_sparse_chunks(unsigned int block_size, off64_t len)
{
	struct count_chunks count_chunks = {0, 0, block_size};

	for_each_data_block(count_data_block, count_file_block, count_fill_block, &count_chunks, block_size);

	if (count_chunks.cur_ptr != len)
		count_chunks.chunks++;

	return count_chunks.chunks;
}

static void ext4_write_data_block(void *priv, off64_t off, void *data, int len)
{
	write_data_block(priv, off, data, len);
}

static void ext4_write_fill_block(void *priv, off64_t off, unsigned int fill_val, int len)
{
	write_fill_block(priv, off, fill_val, len);
}

static void ext4_write_data_file(void *priv, off64_t off, const char *file,
		off64_t offset, int len)
{
	write_data_file(priv, off, file, offset, len);
}

/* Write the filesystem image to a file */
void write_sparse_image(int fd, int gz, int sparse, int crc, unsigned int block_size, off64_t len)
{
	int chunks = count_sparse_chunks(block_size, len);
	struct output_file *out = open_output_fd(fd, block_size, len,
			gz, sparse, chunks, crc);

	if (!out)
		return;

	for_each_data_block(ext4_write_data_block, ext4_write_data_file, ext4_write_fill_block, out, block_size);

	pad_output_file(out, len);

	close_output_file(out);
}
