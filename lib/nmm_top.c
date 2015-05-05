// Original version of BGET downloaded from: http://www.fourmilab.ch/bget/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <asm/io.h>
#include <linux/nmm_top.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/ktime.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/rcupdate.h>
#include <linux/btree.h>

ktime_t ktime_get(void);


/////////////////////////////////////////////////////
/* Authored by Hyunsub Song
 * NTL
 * Simple write/read mechanism for new memory storage
 */

/* void nm_write(unsigned long pfn, char __user *buf, size_t bytes)
{
	// Variables
	void *data_vaddr, *metadata_vaddr;
	struct nm_pfn_struct *nm_pfn;

	// Set metadata
	metadata_vaddr = bget(sizeof(*nm_pfn));
	nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;

	// Set data
	data_vaddr = bget(bytes);

	// Fill nm_pfn_struct's attributes
	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;
	INIT_LIST_HEAD(&nm_pfn->list);
	
    // Insert nm_pfn_struct in nm_pfn_list
	list_add(&nm_pfn->list, &nm_pfn_list);

	// Write data by memset()
	memcpy(data_vaddr, buf, bytes);

	printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);
	printk(KERN_ALERT "nm_write() - buf = %s\n", buf);
}

EXPORT_SYMBOL(nm_write); */

/* For red-black tree */
/* void nm_write(unsigned long pfn, char __user *buf, size_t bytes)
{
	struct nm_pfn_struct *nm_pfn;
	
	nm_pfn = nm_rb_create(pfn, bytes);

	nm_rb_insert(&rb_root_tree, nm_pfn);

	memcpy(nm_pfn->data_vaddr, buf, nm_pfn->bytes);

	printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);
	printk(KERN_ALERT "nm_write() - buf = %s\n", buf);

	// nm_rb_print(&rb_root_tree);
}

EXPORT_SYMBOL(nm_write); */

/* For radix-tree */

size_t nm_top_write(unsigned long pfn, char __user *buf, size_t bytes)
{
	struct nm_pfn_struct *nm_pfn;
	size_t copied;
	unsigned long left;

	nm_pfn = nm_top_rd_create(pfn, bytes);
	nm_top_rd_insert(nm_pfn);

	// printk(KERN_ALERT "nm_write() buf = %s\n", buf);
	left = __copy_from_user(nm_pfn->data_vaddr, buf, nm_pfn->bytes);
	copied = bytes - left;
	
	// printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	// printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	// printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);

	return copied;
}

EXPORT_SYMBOL(nm_top_write);

/* int nm_read(unsigned long pfn, read_descriptor_t *desc)
{
	// Find data through pfn
	struct nm_pfn_struct *nm_pfn;
	// char __user *tmp;
	unsigned long left;
	unsigned long size;

	list_for_each_entry(nm_pfn, &nm_pfn_list, list) {
		if (nm_pfn->pfn == pfn) {
			// tmp = kmalloc(nm_pfn->bytes, GFP_KERNEL);
            // memcpy(tmp, nm_pfn->data_vaddr, nm_pfn->bytes);
			// tmp = (char __user *) nm_pfn->data_vaddr;
			printk(KERN_ALERT "nm_read() - pfn = 0x%x\n", nm_pfn->pfn);
			printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
			printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
			// printk(KERN_ALERT "nm_read() - tmp_buf = %s\n", tmp);
			left = __copy_to_user(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
			if (left == 0) {
				desc->count -= nm_pfn->bytes;
				desc->written += nm_pfn->bytes;
				desc->arg.buf += nm_pfn->bytes;
				size = nm_pfn->bytes;
			}
		}
	}
	return size;
}

EXPORT_SYMBOL(nm_read); */

/* For red-black tree */
/* int nm_read(unsigned long pfn, read_descriptor_t *desc)
{
	struct nm_pfn_struct *nm_pfn;
	unsigned long left, size;

	nm_pfn = nm_rb_search(&rb_root_tree, pfn);
	printk(KERN_ALERT "nm_read() - pfn 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
		
	left = __copy_to_user(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
	if (left == 0) {
		desc->count -= nm_pfn->bytes;
		desc->written += nm_pfn->bytes;
		desc->arg.buf += nm_pfn->bytes;
		size = nm_pfn->bytes;
	}
	
	return size;
}

EXPORT_SYMBOL(nm_read); */

/* For radix-tree */
unsigned long nm_top_read(unsigned long pfn, char __user *buf, size_t size)
{
	struct nm_pfn_struct *nm_pfn;
	unsigned long left;

	nm_pfn = nm_top_rd_search(pfn);

	printk(KERN_ALERT "nm_read() - pfn 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
	
	left = __copy_to_user_inatomic(buf, nm_pfn->data_vaddr, nm_pfn->bytes);
	printk(KERN_ALERT "nm_read() buf = %s\n", buf);
	
	return left;
}

EXPORT_SYMBOL(nm_top_read);

/* For red-black tree */
/* struct nm_pfn_struct* nm_rb_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr, *metadata_vaddr;
	struct nm_pfn_struct* nm_pfn;
	
	metadata_vaddr = bget(sizeof(*nm_pfn));
	nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;

	data_vaddr = bget(bytes);

	rb_init_node(&nm_pfn->node);
	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	return nm_pfn;
}

struct nm_pfn_struct* __nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	struct nm_pfn_struct *this;

	while (*new)
	{
		parent = *new;
		this = rb_entry(parent, struct nm_pfn_struct, node);

		if (new_node->pfn < this->pfn) {
			printk(KERN_ALERT "__rb_insert: left, new->pfn = 0x%x\n", new_node->pfn);
			printk(KERN_ALERT "__rb_insert: left, this->pfn = 0x%x\n", this->pfn);
			printk(KERN_ALERT "__rb_insert: left, this->data_Vaddr = 0x%x\n", this->data_vaddr);
			new = &(*new)->rb_left;
		} else if (new_node->pfn > this->pfn) {
			printk(KERN_ALERT "__rb_insert: right, new->pfn = 0x%x\n", new_node->pfn);
			printk(KERN_ALERT "__rb_insert: right, this->pfn = 0x%x\n", this->pfn);
			printk(KERN_ALERT "__rb_insert: right, this->data_Vaddr = 0x%x\n", this->data_vaddr);
			new = &(*new)->rb_right;
		} else {
			printk(KERN_ALERT "__rb_insert: this\n");
			return this;
		}
	}
	rb_link_node(&new_node->node, parent, new);

	return NULL;
}

struct nm_pfn_struct* nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node)
{
	struct nm_pfn_struct *ret;
	if ((ret = __nm_rb_insert(root, new_node)))
		goto out;
	rb_insert_color(&new_node->node, root);
out:
	return ret;
}

struct nm_pfn_struct* nm_rb_search(struct rb_root *root, unsigned long pfn)
{
	struct rb_node *new = root->rb_node;
	struct nm_pfn_struct *this;

	while (new)
	{
		this = rb_entry(new, struct nm_pfn_struct, node);

		if (pfn < this->pfn)
			new = new->rb_left;
		else if (pfn > this->pfn)
			new = new->rb_right;
		else
			return this;
	}
	return NULL;
}

void __nm_rb_print(struct rb_node *tmp_node, int depth, int destination)
{
	struct nm_pfn_struct *this;
	this = rb_entry(tmp_node, struct nm_pfn_struct, node);
	int i;
	for (i = 0; i < depth; i++)
		printk(KERN_ALERT "\t");

	if (destination == 0)
		printk(KERN_ALERT "ROOT");
	else if (destination == 1)
		printk(KERN_ALERT "LEFT");
	else
		printk(KERN_ALERT "RIGHT");

	printk(KERN_ALERT "0x%x", this->pfn);
	printk(KERN_ALERT "0x%x", this->data_vaddr);
	printk(KERN_ALERT "0x%d\n", this->bytes);

	if (tmp_node->rb_left)
		__nm_rb_print(tmp_node->rb_left, depth + 1, 1);

	if (tmp_node->rb_right)
		__nm_rb_print(tmp_node->rb_right, depth + 1, 2);
}

void nm_rb_print(struct rb_root *root)
{
	struct rb_node *new = root->rb_node;
	__nm_rb_print(new, 1, 0);
} */

/* For radix-tree */
/* struct nm_pfn_struct* nm_rd_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr;
	struct nm_pfn_struct* nm_pfn;

	// metadata_vaddr = bget(sizeof(*nm_pfn));
	// nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;
	nm_pfn = kmalloc(sizeof(*nm_pfn), GFP_KERNEL);

	// data_vaddr = bget(bytes);
	data_vaddr = kmalloc(bytes, GFP_KERNEL);

	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	data_access_num++;
	printk(KERN_ALERT "sensong: nm_rd_create - data_access_num = %d\n", data_access_num);

	return nm_pfn;
} */

/* For radix-tree and fixed metadata */
struct nm_pfn_struct* nm_top_rd_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr;
	struct nm_pfn_struct* nm_pfn;
	
	// metadata_vaddr = bget(sizeof(*nm_pfn));
	// nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;
	
	nm_pfn = kmalloc(sizeof(*nm_pfn), GFP_KERNEL);
	
	// nm_pfn = &(metadata_start_addr->nm_pfn[data_access_num]);

	// data_vaddr = bget(bytes);
	data_vaddr = kmalloc(bytes, GFP_KERNEL);

	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	// data_access_num++;
	// printk(KERN_ALERT "sensong: nm_rd_create - data_access_num = %d\n", data_access_num);

	// return &(metadata_start_addr->nm_pfn[data_access_num - 1]);
	return nm_pfn;
}

void nm_top_rd_insert(struct nm_pfn_struct *new_node)
{
	// spin_lock_irq(tree_lock);
	// radix_tree_insert(rd_root, new_node->pfn, new_node);
	// spin_unlock_irq(tree_lock);
	
	// b+ tree insert
	int ret;

	spin_lock_irq(&top_btree_lock);
	ret = btree_insert(&top_b_root, &btree_geo64, &(new_node->pfn), new_node, GFP_KERNEL);	
	spin_unlock_irq(&top_btree_lock);
}

struct nm_pfn_struct* nm_top_rd_search(unsigned long pfn)
{
	struct nm_pfn_struct *nm_pfn;

	// rcu_read_lock();
	// nm_pfn = radix_tree_lookup(rd_root, pfn);
	// rcu_read_unlock();
	
	// b+ tree search
	
	// printk(KERN_ALERT "nm_rd_search: pfn = 0x%x\n", pfn);
	
	rcu_read_lock();
	nm_pfn = btree_lookup(&top_b_root, &btree_geo64, &pfn);
	rcu_read_unlock();

	return nm_pfn;
}
/////////////////////////////////////////////////////

static int __init init_nmm_top(void)
{	
	printk(KERN_ALERT "[sensong] nmm_top module start!!!\n");
	/* Fixed metadata */
	// void *tmp_vaddr;

	/* For radix-tree */
	// INIT_RADIX_TREE(&rd_root, GFP_ATOMIC);
	
	/* For b+ tree */
	btree_init(&top_b_root);	
	spin_lock_init(&top_btree_lock);
	//////////////////////////////////////
	return 0;
}

static void __exit exit_nmm_top(void)
{
	printk(KERN_ALERT "[sensong] nmm_top module end!!!\n");
}

module_init(init_nmm_top)
module_exit(exit_nmm_top)

MODULE_LICENSE("GPL");
