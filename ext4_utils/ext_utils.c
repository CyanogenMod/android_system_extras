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

#include "ext4_utils.h"
#include "ext4.h"

/* returns 1 if a is a power of b */
static int is_power_of(int a, int b)
{
	while (a > b) {
		if (a % b)
			return 0;
		a /= b;
	}

	return (a == b) ? 1 : 0;
}

/* Returns 1 if the bg contains a backup superblock.  On filesystems with
   the sparse_super feature, only block groups 0, 1, and powers of 3, 5,
   and 7 have backup superblocks.  Otherwise, all block groups have backup
   superblocks */
int ext4_bg_has_super_block(int bg)
{
	/* Without sparse_super, every block group has a superblock */
	if (!(info.feat_ro_compat & EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER))
		return 1;

	if (bg == 0 || bg == 1)
		return 1;

	if (is_power_of(bg, 3) || is_power_of(bg, 5) || is_power_of(bg, 7))
		return 1;

	return 0;
}
