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

#ifndef EXTENT_H
#define EXTENT_H

#include "types.h"

typedef enum {
	EXTENT_TYPE_BOOT,
	EXTENT_TYPE_INFO,
	EXTENT_TYPE_FAT,
	EXTENT_TYPE_FILE,
	EXTENT_TYPE_DIR
} extent_type;

struct extent {
	offset_t start;
	offset_t len;
	extent_type type;

	struct extent *next;
};

#endif
