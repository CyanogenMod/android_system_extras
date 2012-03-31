#include <sys/types.h>

#define EXT4_XATTR_MAGIC 0xEA020000
#define EXT4_XATTR_INDEX_SECURITY 6

struct ext4_xattr_entry {
    __u8 e_name_len;
    __u8 e_name_index;
    __le16 e_value_offs;
    __le32 e_value_block;
    __le32 e_value_size;
    __le32 e_hash;
    char e_name[0];
};

#define EXT4_XATTR_PAD_BITS 2
#define EXT4_XATTR_PAD (1<<EXT4_XATTR_PAD_BITS)
#define EXT4_XATTR_ROUND (EXT4_XATTR_PAD-1)
#define EXT4_XATTR_LEN(name_len) \
    (((name_len) + EXT4_XATTR_ROUND + \
    sizeof(struct ext4_xattr_entry)) & ~EXT4_XATTR_ROUND)
#define EXT4_XATTR_SIZE(size) \
    (((size) + EXT4_XATTR_ROUND) & ~EXT4_XATTR_ROUND)
