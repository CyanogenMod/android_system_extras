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

#ifndef _LIBSPARSE_SPARSE_H_
#define _LIBSPARSE_SPARSE_H_

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__MACH__)
#define off64_t off_t
#endif

void write_sparse_image(int fd, int gz, int sparse, int crc, unsigned int block_size, off64_t len);
void queue_data_block(void *data, unsigned int len, unsigned int block);
void queue_fill_block(unsigned int fill_val, unsigned int len, unsigned int block);
void queue_data_file(const char *filename, off64_t offset, unsigned int len,
		unsigned int block);
void free_data_blocks();

#endif
