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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <libgen.h>

#if defined(__linux__)
#include <linux/fs.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/disk.h>
#endif

#include "make_ext4fs.h"
#include "output_file.h"
#include "ext4_utils.h"
#include "allocate.h"
#include "ext_utils.h"
#include "backed_block.h"
#include "contents.h"
#include "extent.h"
#include "indirect.h"
#include "uuid.h"

#include "jbd2.h"
#include "ext4.h"

#ifdef ANDROID
#include <private/android_filesystem_config.h>
#endif

/* TODO: Not implemented:
   Allocating blocks in the same block group as the file inode
   Hash or binary tree directories
   Special files: sockets, devices, fifos
 */

int force = 0;

struct fs_info info;
struct fs_aux_info aux_info;

/* Write the filesystem image to a file */
static void write_ext4_image(const char *filename, int gz)
{
	int ret = 0;
	struct output_file *out = open_output_file(filename, gz);
	off_t off;

	if (!out)
		return;

	write_data_block(out, 1024, (u8*)aux_info.sb, 1024);

	write_data_block(out, (aux_info.first_data_block + 1) * info.block_size,
			 (u8*)aux_info.bg_desc, 
			 aux_info.bg_desc_blocks * info.block_size);

	for_each_data_block(write_data_block, write_data_file, out);

	write_data_block(out, info.len - 1, (u8*)"", 1);

	close_output_file(out);
}

/* Compute the rest of the parameters of the filesystem from the basic info */
static void ext4_create_fs_aux_info()
{
	aux_info.first_data_block = (info.block_size > 1024) ? 0 : 1;
	aux_info.len_blocks = info.len / info.block_size;
	aux_info.inode_table_blocks = DIV_ROUND_UP(info.inodes_per_group * info.inode_size,
		info.block_size);
	aux_info.groups = DIV_ROUND_UP(aux_info.len_blocks - aux_info.first_data_block,
		info.blocks_per_group);
	aux_info.blocks_per_ind = info.block_size / sizeof(u32);
	aux_info.blocks_per_dind = aux_info.blocks_per_ind * aux_info.blocks_per_ind;
	aux_info.blocks_per_tind = aux_info.blocks_per_dind * aux_info.blocks_per_dind;

	aux_info.bg_desc_blocks =
		DIV_ROUND_UP(aux_info.groups * sizeof(struct ext2_group_desc),
			info.block_size);

	aux_info.bg_desc_reserve_blocks =
		DIV_ROUND_UP(aux_info.groups * 1024 * sizeof(struct ext2_group_desc),
			info.block_size) - aux_info.bg_desc_blocks;

	if (aux_info.bg_desc_reserve_blocks > aux_info.blocks_per_ind)
		aux_info.bg_desc_reserve_blocks = aux_info.blocks_per_ind;

	aux_info.default_i_flags = EXT4_NOATIME_FL;

	u32 last_group_size = aux_info.len_blocks % info.blocks_per_group;
	u32 last_header_size = 2 + aux_info.inode_table_blocks;
	if (ext4_bg_has_super_block(aux_info.groups - 1))
		last_header_size += 1 + aux_info.bg_desc_blocks +
			aux_info.bg_desc_reserve_blocks;
	if (last_group_size > 0 && last_group_size < last_header_size) {
		aux_info.groups--;
		aux_info.len_blocks -= last_group_size;
	}

	aux_info.sb = calloc(info.block_size, 1);
	if (!aux_info.sb)
		critical_error_errno("calloc");

	aux_info.bg_desc = calloc(info.block_size, aux_info.bg_desc_blocks);
	if (!aux_info.bg_desc)
		critical_error_errno("calloc");
}

void ext4_free_fs_aux_info()
{
	free(aux_info.sb);
	free(aux_info.bg_desc);
}

/* Fill in the superblock memory buffer based on the filesystem parameters */
static void ext4_fill_in_sb()
{
	unsigned int i;
	struct ext4_super_block *sb = aux_info.sb;

	sb->s_inodes_count = info.inodes_per_group * aux_info.groups;
	sb->s_blocks_count_lo = aux_info.len_blocks;
	sb->s_r_blocks_count_lo = 0;
	sb->s_free_blocks_count_lo = 0;
	sb->s_free_inodes_count = 0;
	sb->s_first_data_block = aux_info.first_data_block;
	sb->s_log_block_size = log_2(info.block_size / 1024);
	sb->s_obso_log_frag_size = log_2(info.block_size / 1024);
	sb->s_blocks_per_group = info.blocks_per_group;
	sb->s_obso_frags_per_group = info.blocks_per_group;
	sb->s_inodes_per_group = info.inodes_per_group;
	sb->s_mtime = 0;
	sb->s_wtime = 0;
	sb->s_mnt_count = 0;
	sb->s_max_mnt_count = 0xFFFF;
	sb->s_magic = EXT4_SUPER_MAGIC;
	sb->s_state = EXT4_VALID_FS;
	sb->s_errors = EXT4_ERRORS_RO;
	sb->s_minor_rev_level = 0;
	sb->s_lastcheck = 0;
	sb->s_checkinterval = 0;
	sb->s_creator_os = EXT4_OS_LINUX;
	sb->s_rev_level = EXT4_DYNAMIC_REV;
	sb->s_def_resuid = EXT4_DEF_RESUID;
	sb->s_def_resgid = EXT4_DEF_RESGID;

	sb->s_first_ino = EXT4_GOOD_OLD_FIRST_INO;
	sb->s_inode_size = info.inode_size;
	sb->s_block_group_nr = 0;
	sb->s_feature_compat = info.feat_compat;
	sb->s_feature_incompat = info.feat_incompat;
	sb->s_feature_ro_compat = info.feat_ro_compat;
	generate_uuid("extandroid/make_ext4fs", info.label, sb->s_uuid);
	memset(sb->s_volume_name, 0, sizeof(sb->s_volume_name));
	strncpy(sb->s_volume_name, info.label, sizeof(sb->s_volume_name));
	memset(sb->s_last_mounted, 0, sizeof(sb->s_last_mounted));
	sb->s_algorithm_usage_bitmap = 0;

	sb->s_reserved_gdt_blocks = aux_info.bg_desc_reserve_blocks;
	sb->s_prealloc_blocks = 0;
	sb->s_prealloc_dir_blocks = 0;

	//memcpy(sb->s_journal_uuid, sb->s_uuid, sizeof(sb->s_journal_uuid));
	if (info.feat_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL)
		sb->s_journal_inum = EXT4_JOURNAL_INO;
	sb->s_journal_dev = 0;
	sb->s_last_orphan = 0;
	sb->s_hash_seed[0] = 0; /* FIXME */
	sb->s_def_hash_version = DX_HASH_TEA;
	sb->s_reserved_char_pad = EXT4_JNL_BACKUP_BLOCKS;
	sb->s_desc_size = sizeof(struct ext2_group_desc);
	sb->s_default_mount_opts = 0; /* FIXME */
	sb->s_first_meta_bg = 0;
	sb->s_mkfs_time = 0;
	//sb->s_jnl_blocks[17]; /* FIXME */

	sb->s_blocks_count_hi = aux_info.len_blocks >> 32;
	sb->s_r_blocks_count_hi = 0;
	sb->s_free_blocks_count_hi = 0;
	sb->s_min_extra_isize = sizeof(struct ext4_inode) -
		EXT4_GOOD_OLD_INODE_SIZE;
	sb->s_want_extra_isize = sizeof(struct ext4_inode) -
		EXT4_GOOD_OLD_INODE_SIZE;
	sb->s_flags = 0;
	sb->s_raid_stride = 0;
	sb->s_mmp_interval = 0;
	sb->s_mmp_block = 0;
	sb->s_raid_stripe_width = 0;
	sb->s_log_groups_per_flex = 0;
	sb->s_kbytes_written = 0;

	for (i = 0; i < aux_info.groups; i++) {
		u64 group_start_block = aux_info.first_data_block + i *
			info.blocks_per_group;
		u32 header_size = 0;
		if (ext4_bg_has_super_block(i)) {
			if (i != 0) {
				queue_data_block((u8 *)sb, info.block_size, group_start_block);
				queue_data_block((u8 *)aux_info.bg_desc,
					aux_info.bg_desc_blocks * info.block_size,
					group_start_block + 1);
			}
			header_size = 1 + aux_info.bg_desc_blocks + aux_info.bg_desc_reserve_blocks;
		}

		aux_info.bg_desc[i].bg_block_bitmap = group_start_block + header_size;
		aux_info.bg_desc[i].bg_inode_bitmap = group_start_block + header_size + 1;
		aux_info.bg_desc[i].bg_inode_table = group_start_block + header_size + 2;

		aux_info.bg_desc[i].bg_free_blocks_count = sb->s_blocks_per_group;
		aux_info.bg_desc[i].bg_free_inodes_count = sb->s_inodes_per_group;
		aux_info.bg_desc[i].bg_used_dirs_count = 0;
	}
}

static void ext4_create_resize_inode()
{
	struct block_allocation *reserve_inode_alloc = create_allocation();
	u32 reserve_inode_len = 0;
	unsigned int i;

	struct ext4_inode *inode = get_inode(EXT4_RESIZE_INO);
	if (inode == NULL) {
		error("failed to get resize inode");
		return;
	}

	for (i = 0; i < aux_info.groups; i++) {
		if (ext4_bg_has_super_block(i)) {
			u64 group_start_block = aux_info.first_data_block + i *
				info.blocks_per_group;
			u32 reserved_block_start = group_start_block + 1 +
				aux_info.bg_desc_blocks;
			u32 reserved_block_len = aux_info.bg_desc_reserve_blocks;
			append_region(reserve_inode_alloc, reserved_block_start,
				reserved_block_len, i);
			reserve_inode_len += reserved_block_len;
		}
	}

	inode_attach_resize(inode, reserve_inode_alloc);

	inode->i_mode = S_IFREG | S_IRUSR | S_IWUSR;
	inode->i_links_count = 1;

	free_alloc(reserve_inode_alloc);
}

/* Allocate the blocks to hold a journal inode and connect them to the
   reserved journal inode */
static void ext4_create_journal_inode()
{
	struct ext4_inode *inode = get_inode(EXT4_JOURNAL_INO);
	if (inode == NULL) {
		error("failed to get journal inode");
		return;
	}

	u8 *journal_data = inode_allocate_data_extents(inode,
			info.journal_blocks * info.block_size,
			info.block_size);
	if (!journal_data) {
		error("failed to allocate extents for journal data");
		return;
	}

	inode->i_mode = S_IFREG | S_IRUSR | S_IWUSR;
	inode->i_links_count = 1;

	journal_superblock_t *jsb = (journal_superblock_t *)journal_data;
	jsb->s_header.h_magic = htonl(JBD2_MAGIC_NUMBER);
	jsb->s_header.h_blocktype = htonl(JBD2_SUPERBLOCK_V2);
	jsb->s_blocksize = htonl(info.block_size);
	jsb->s_maxlen = htonl(info.journal_blocks);
	jsb->s_nr_users = htonl(1);
	jsb->s_first = htonl(1);
	jsb->s_sequence = htonl(1);

	memcpy(aux_info.sb->s_jnl_blocks, &inode->i_block, sizeof(inode->i_block));
}

/* Update the number of free blocks and inodes in the filesystem and in each
   block group */
static void ext4_update_free()
{
	unsigned int i;

	for (i = 0; i < aux_info.groups; i++) {
		u32 bg_free_blocks = get_free_blocks(i);
		u32 bg_free_inodes = get_free_inodes(i);

		aux_info.bg_desc[i].bg_free_blocks_count = bg_free_blocks;
		aux_info.sb->s_free_blocks_count_lo += bg_free_blocks;

		aux_info.bg_desc[i].bg_free_inodes_count = bg_free_inodes;
		aux_info.sb->s_free_inodes_count += bg_free_inodes;

		aux_info.bg_desc[i].bg_used_dirs_count += get_directories(i);
	}
}

static int filter_dot(const struct dirent *d)
{
	return (strcmp(d->d_name, "..") && strcmp(d->d_name, "."));
}

static u32 build_default_directory_structure()
{
	u32 inode;
	u32 root_inode;
	struct dentry dentries = {
			.filename = "lost+found",
			.file_type = EXT4_FT_DIR,
			.mode = S_IRWXU,
			.uid = 0,
			.gid = 0
	};
	root_inode = make_directory(0, 1, &dentries, 1);
	inode = make_directory(root_inode, 0, NULL, 0);
	*dentries.inode = inode;

	return root_inode;
}

/* Read a local directory and create the same tree in the generated filesystem.
   Calls itself recursively with each directory in the given directory */
static u32 build_directory_structure(const char *full_path, const char *dir_path,
		u32 dir_inode, int android)
{
	int entries = 0;
	struct dentry *dentries;
	struct dirent **namelist;
	struct stat stat;
	int ret;
	int i;
	u32 inode;
	u32 entry_inode;
	u32 dirs = 0;

	entries = scandir(full_path, &namelist, filter_dot, (void*)alphasort);
	if (entries < 0) {
		error_errno("scandir");
		return EXT4_ALLOCATE_FAILED;
	}

	dentries = calloc(entries, sizeof(struct dentry));
	if (dentries == NULL)
		critical_error_errno("malloc");

	for (i = 0; i < entries; i++) {
		dentries[i].filename = strdup(namelist[i]->d_name);
		if (dentries[i].filename == NULL)
			critical_error_errno("strdup");

		asprintf(&dentries[i].path, "%s/%s", dir_path, namelist[i]->d_name);
		asprintf(&dentries[i].full_path, "%s/%s", full_path, namelist[i]->d_name);

		free(namelist[i]);

		ret = lstat(dentries[i].full_path, &stat);
		if (ret < 0) {
			error_errno("lstat");
			i--;
			entries--;
			continue;
		}

		dentries[i].size = stat.st_size;
		dentries[i].mode = stat.st_mode & (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
		if (android) {
#ifdef ANDROID
			unsigned int mode = 0;
			unsigned int uid = 0;
			unsigned int gid = 0;
			int dir = S_ISDIR(stat.st_mode);
			fs_config(dentries[i].path, dir, &uid, &gid, &mode);
			dentries[i].mode = mode;
			dentries[i].uid = uid;
			dentries[i].gid = gid;
#else
			error("can't set android permissions - built without android support");
#endif
		}

		if (S_ISREG(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_REG_FILE;
		} else if (S_ISDIR(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_DIR;
			dirs++;
		} else if (S_ISCHR(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_CHRDEV;
		} else if (S_ISBLK(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_BLKDEV;
		} else if (S_ISFIFO(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_FIFO;
		} else if (S_ISSOCK(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_SOCK;
		} else if (S_ISLNK(stat.st_mode)) {
			dentries[i].file_type = EXT4_FT_SYMLINK;
			dentries[i].link = calloc(info.block_size, 1);
			readlink(dentries[i].full_path, dentries[i].link, info.block_size - 1);
		} else {
			error("unknown file type on %s", dentries[i].path);
			i--;
			entries--;
		}
	}
	free(namelist);

	inode = make_directory(dir_inode, entries, dentries, dirs);

	for (i = 0; i < entries; i++) {
		if (dentries[i].file_type == EXT4_FT_REG_FILE) {
			entry_inode = make_file(dentries[i].full_path, dentries[i].size);
		} else if (dentries[i].file_type == EXT4_FT_DIR) {
			entry_inode = build_directory_structure(dentries[i].full_path,
					dentries[i].path, inode, android);
		} else if (dentries[i].file_type == EXT4_FT_SYMLINK) {
			entry_inode = make_link(dentries[i].full_path, dentries[i].link);
		} else {
			error("unknown file type on %s", dentries[i].path);
			entry_inode = 0;
		}
		*dentries[i].inode = entry_inode;

		ret = inode_set_permissions(entry_inode, dentries[i].mode,
				dentries[i].uid, dentries[i].gid);
		if (ret)
			error("failed to set permissions on %s\n", dentries[i].path);

		free(dentries[i].path);
		free(dentries[i].full_path);
		free(dentries[i].link);
		free((void *)dentries[i].filename);
	}

	free(dentries);
	return inode;
}

static u32 compute_block_size()
{
	return 4096;
}

static u32 compute_blocks_per_group()
{
	return info.block_size * 8;
}

static u32 compute_inodes()
{
	return DIV_ROUND_UP(info.len, info.block_size) / 4;
}

static u32 compute_inodes_per_group()
{
	u32 blocks = DIV_ROUND_UP(info.len, info.block_size);
	u32 block_groups = DIV_ROUND_UP(blocks, info.blocks_per_group);
	return DIV_ROUND_UP(info.inodes, block_groups);
}

static u64 get_block_device_size(const char *filename)
{
	int fd = open(filename, O_RDONLY);
	u64 size = 0;
	int ret;

	if (fd < 0)
		return 0;

#if defined(__linux__)
	ret = ioctl(fd, BLKGETSIZE64, &size);
#elif defined(__APPLE__) && defined(__MACH__)
	ret = ioctl(fd, DKIOCGETBLOCKCOUNT, &size);
#else
	return 0;
#endif

	close(fd);

	if (ret)
		return 0;

	return size;
}

static u64 get_file_size(const char *filename)
{
	struct stat buf;
	int ret;

	ret = stat(filename, &buf);
	if (ret)
		return 0;

	if (S_ISREG(buf.st_mode))
		return buf.st_size;
	else if (S_ISBLK(buf.st_mode))
		return get_block_device_size(filename);
	else
		return 0;
}

static void usage(char *path)
{
	fprintf(stderr, "%s [ -l <len> ] [ -j <journal size> ] [ -b <block_size> ]\n", basename(path));
	fprintf(stderr, "    [ -g <blocks per group> ] [ -i <inodes> ] [ -I <inode size> ]\n");
	fprintf(stderr, "    [ -L <label> ] [ -f ] [ -a <android mountpoint> ]\n");
	fprintf(stderr, "    <filename> [<directory>]\n");
}

static u64 parse_num(const char *arg)
{
	char *endptr;
	u64 num = strtoull(arg, &endptr, 10);
	if (*endptr == 'k' || *endptr == 'K')
		num *= 1024LL;
	else if (*endptr == 'm' || *endptr == 'M')
		num *= 1024LL * 1024LL;
	else if (*endptr == 'g' || *endptr == 'G')
		num *= 1024LL * 1024LL * 1024LL;

	return num;
}

int main(int argc, char **argv)
{
	int opt;
	const char *filename = NULL;
	const char *directory = NULL;
	char *mountpoint = "";
	int android = 0;
	int gzip = 0;
	u32 root_inode_num;
	u16 root_mode;

	while ((opt = getopt(argc, argv, "l:j:b:g:i:I:L:a:fz")) != -1) {
		switch (opt) {
		case 'l':
			info.len = parse_num(optarg);
			break;
		case 'j':
			info.journal_blocks = parse_num(optarg);
			break;
		case 'b':
			info.block_size = parse_num(optarg);
			break;
		case 'g':
			info.blocks_per_group = parse_num(optarg);
			break;
		case 'i':
			info.inodes = parse_num(optarg);
			break;
		case 'I':
			info.inode_size = parse_num(optarg);
			break;
		case 'L':
			info.label = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'a':
			android = 1;
			mountpoint = optarg;
			break;
		case 'z':
			gzip = 1;
			break;
		default: /* '?' */
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Expected filename after options\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	filename = argv[optind++];

	if (optind < argc)
		directory = argv[optind++];

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (info.len == 0)
		info.len = get_file_size(filename);

	if (info.len <= 0) {
		fprintf(stderr, "Need size of filesystem\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (info.journal_blocks > 0)
		info.feat_compat = EXT4_FEATURE_COMPAT_HAS_JOURNAL;

	if (info.block_size <= 0)
		info.block_size = compute_block_size();

	if (info.blocks_per_group <= 0)
		info.blocks_per_group = compute_blocks_per_group();

	if (info.inodes <= 0)
		info.inodes = compute_inodes();

	if (info.inode_size <= 0)
		info.inode_size = 256;

	if (info.label == NULL)
		info.label = "";

	info.inodes_per_group = compute_inodes_per_group();

	info.feat_compat |=
			EXT4_FEATURE_COMPAT_RESIZE_INODE;

	info.feat_ro_compat |=
			EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER |
			EXT4_FEATURE_RO_COMPAT_LARGE_FILE;

	info.feat_incompat |=
			EXT4_FEATURE_INCOMPAT_EXTENTS |
			EXT4_FEATURE_INCOMPAT_FILETYPE;


	printf("Creating filesystem with parameters:\n");
	printf("    Size: %llu\n", info.len);
	printf("    Block size: %d\n", info.block_size);
	printf("    Blocks per group: %d\n", info.blocks_per_group);
	printf("    Inodes per group: %d\n", info.inodes_per_group);
	printf("    Inode size: %d\n", info.inode_size);
	printf("    Label: %s\n", info.label);

	ext4_create_fs_aux_info();

	printf("    Blocks: %llu\n", aux_info.len_blocks);
	printf("    Block groups: %d\n", aux_info.groups);
	printf("    Reserved block group size: %d\n", aux_info.bg_desc_reserve_blocks);

	block_allocator_init();

	ext4_fill_in_sb();

	if (reserve_inodes(0, 10) == EXT4_ALLOCATE_FAILED)
		error("failed to reserve first 10 inodes");

	if (info.feat_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL)
		ext4_create_journal_inode();

	if (info.feat_compat & EXT4_FEATURE_COMPAT_RESIZE_INODE)
		ext4_create_resize_inode();

	if (directory)
		root_inode_num = build_directory_structure(directory, mountpoint, 0, android);
	else
		root_inode_num = build_default_directory_structure();
	
	root_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	inode_set_permissions(root_inode_num, root_mode, 0, 0);

	ext4_update_free();

	printf("Created filesystem with %d/%d inodes and %d/%d blocks\n",
			aux_info.sb->s_inodes_count - aux_info.sb->s_free_inodes_count,
			aux_info.sb->s_inodes_count,
			aux_info.sb->s_blocks_count_lo - aux_info.sb->s_free_blocks_count_lo,
			aux_info.sb->s_blocks_count_lo);

	write_ext4_image(filename, gzip);

	return 0;
}
