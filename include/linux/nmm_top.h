#ifndef NMM_TOP_H
#define NMM_TOP_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/btree.h>

//////////////////////////////////////////////////////
// Authored by Hyunsub Song
// NTL

/* For linked list */
/* struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
	struct list_head list;
};

static LIST_HEAD(nm_pfn_list); */

/* For red-black tree */
/* struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
	struct rb_node node;
};

static struct rb_root rb_root_tree = RB_ROOT;*/

/* For radix-tree */
struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
};

/* For b+ tree */
static struct btree_head top_b_root;
static spinlock_t top_btree_lock;


// static struct radix_tree_root rd_root;

/* test for check number of write request */
/* struct nm_pfn_struct_array {
	struct nm_pfn_struct nm_pfn[300000];
};

static struct nm_pfn_struct_array *metadata_start_addr;
static int data_access_num = 0; */
///////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// Authored by Hyunsub Song
// NTL
extern size_t nm_top_write(unsigned long pfn, char __user *buf, size_t bytes);
extern unsigned long nm_top_read(unsigned long pfn, char __user *buf, size_t size);

/* For red-black tree */
// struct nm_pfn_struct* nm_rb_create(unsigned long pfn, size_t bytes);
// struct nm_pfn_struct* __nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node);
// struct nm_pfn_struct* nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node);
// struct nm_pfn_struct* nm_rb_search(struct rb_root *root, unsigned long pfn);
// void __nm_rb_print(struct rb_node *tmp_node, int depth, int destination);
// void nm_rb_print(struct rb_root *root);

/* For radix-tree */
struct nm_pfn_struct* nm_top_rd_create(unsigned long pfn, size_t bytes);
void nm_top_rd_insert(struct nm_pfn_struct *new_node);
struct nm_pfn_struct* nm_top_rd_search(unsigned long pfn);
////////////////////////////////////////////////////////

#endif
