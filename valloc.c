// This allocator makes some assumptions about your system:
// - PAGE_SIZE is defined in sys/param.h
// - mmap accepts MAP_ANONYMOUS
// WARNING: This allocator is very much not thread-safe

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include "valloc.h"

// Helpers {{{
#define _valloc_error() do { errno = ENOMEM; return NULL; } while (0)

// Align value to a multiple of the power of two align, rounding down
#define _valloc_aligndown(value, align) ((value) & ~((align)-1))

// Align value to a multiple of the power of two align, rounding up
// If value is already aligned to align, it is returned unmodified
// align may be evaluated more than once
#define _valloc_alignup(value, align) _valloc_aligndown(value + align - 1, align)
// }}}

// Treap implementation {{{
// This treap is used to store free blocks of memory
// Heap-ordering is used during allocation, as we split the largest free block in half to ensure a good spread of allocations
// Tree-ordering is used during freeing to find adjacent free blocks to merge with
// The heap key is the length of the block; the tree key is its address
typedef struct treap_node {
	size_t len;
	struct treap_node *left, *right;
} treap_t;

static treap_t *blocks = NULL;

static treap_t *_treap_rotr(treap_t *root) {
	treap_t *pivot = root->left;
	root->left = pivot->right;
	pivot->right = root;
	return pivot;
}

static treap_t *_treap_rotl(treap_t *root) {
	treap_t *pivot = root->right;
	root->right = pivot->left;
	pivot->left = root;
	return pivot;
}

static treap_t *_treap_insert(treap_t *root, treap_t *node) {
	if (node < root) {
		// Insert on the left
		if (root->left) root = _treap_insert(root->left, node);
		else root->left = node;

		// Ensure heap order
		if (node->len > root->len) root = _treap_rotr(root);
	} else {
		// Insert on the right
		if (root->right) root = _treap_insert(root->right, node);
		else root->right = node;

		// Ensure heap order
		if (node->len > root->len) root = _treap_rotl(root);
	}
	return root;
}

static void treap_insert(treap_t *node) {
	node->left = NULL;
	node->right = NULL;
	if (blocks) blocks = _treap_insert(blocks, node);
	else blocks = node;
}

static treap_t *_treap_siftdown(treap_t *root) {
	treap_t **node = &root;
	while (1) {
		if ((*node)->left && (*node)->len < (*node)->left->len) {
			*node = _treap_rotr(*node);
			node = &(*node)->right;
		} else if ((*node)->right && (*node)->len < (*node)->right->len) {
			*node = _treap_rotl(*node);
			node = &(*node)->left;
		} else {
			break;
		}
	}
	return root;
}

// Returns the new root node of the subtree
static treap_t *_treap_delete(treap_t *node) {
	// If we have two children, swap the root node with the next node in the subtree, and sift down
	if (node->left && node->right) {
		// Find the next node
		treap_t **next = &node->right;
		while ((*next)->left) next = &(*next)->left;

		// Move next into the place of the root node and replace it with its child (if any)
		treap_t *newroot = *next;
		*next = newroot->right;
		newroot->left = node->left;
		newroot->right = node->right;

		// Sift down and return the new root node
		return _treap_siftdown(newroot);
	}

	// If we have one child, replace the node with that child
	if (node->left) return node->left;
	if (node->right) return node->right;

	// Otherwise, we have no children so the subtree is now empty
	return NULL;
}

static treap_t *treap_peek(void) {
	return blocks;
}

static treap_t *treap_pop(void) {
	if (!blocks) return NULL;
	treap_t *node = blocks;
	blocks = _treap_delete(node);
	return node;
}

#define _treap_search_alg(key) \
	treap_t **node = &blocks; \
	while (1) { \
		if (!*node) return NULL; /* Couldn't find it */ \
		if (addr > (void *)(key)) { \
			node = &(*node)->right; \
		} else if (addr < (void *)(key)) { \
			node = &(*node)->left; \
		} else { \
			break; \
		} \
	}

// Search for a node whose address is addr
static treap_t **treap_search_start(void *addr) {
	_treap_search_alg(*node);
	return node;
}

// Search for a node whose address+len is addr
static treap_t **treap_search_end(void *addr) {
	_treap_search_alg((char *)*node + (*node)->len);
	return node;
}

// Remove a node found by treap_search_*
static void treap_remove(treap_t **node) {
	*node = _treap_delete(*node);
}

// Search for and remove a node whose address is addr
static treap_t *treap_remove_start(void *addr) {
	treap_t **node = treap_search_start(addr);
	if (!node) return NULL;
	treap_t *ret = *node;
	treap_remove(node);
	return ret;
}

// Search for and remove a node whose address+len is addr
static treap_t *treap_remove_end(void *addr) {
	treap_t **node = treap_search_end(addr);
	if (!node) return NULL;
	treap_t *ret = *node;
	treap_remove(node);
	return ret;
}

// }}}

// Block management {{{
static treap_t *_valloc_create_block(void *mem, size_t len) {
	if (len < sizeof (treap_t)) return NULL;

	// Create a block for the memory
	treap_t *node = mem;
	node->len = len;

	// Search for a block to the left
	treap_t *left = treap_remove_end(mem);
	// Search for a block to the right
	treap_t *right = treap_remove_start((char *)mem + len);

	if (left) {
		// Merge with left block
		left->len += node->len;
		node = left;
	}
	if (right) {
		// Merge with right block
		node->len += right->len;
	}

	return node;
}

static void _valloc_add_block(void *mem, size_t len) {
	treap_t *node = _valloc_create_block(mem, len);
	if (node) treap_insert(node);
}

static void *_valloc_split_block(treap_t *node, size_t len) {
	size_t left_len = node->len - len;
	size_t right_len = left_len/2;
	left_len -= right_len;

	// Place the leftover bits back in the pool
	// We don't use _valloc_add_block because there will never be anything to merge with
	if (left_len >= sizeof (treap_t)) {
		treap_t *left = node;
		left->len = left_len;
		treap_insert(left);
	}
	if (right_len >= sizeof (treap_t)) {
		treap_t *right = (void *)((char *)node + left_len + len);
		right->len = right_len;
		treap_insert(right);
	}

	return (char *)node + left_len;
}
// }}}

// Allocation {{{
static treap_t *_valloc_map(size_t len) {
	// This is the hint address for the next page to be allocated
	// It is used so that we can attempt to allocate pages adjacent to each other in order to
	// allow merging of blocks across pages
	static void *page_hint = NULL;

	size_t map_len = _valloc_alignup(len, PAGE_SIZE);
	void *mapped = mmap(page_hint, map_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (mapped == MAP_FAILED) return NULL;

	// Update the page hint
	page_hint = (char *)mapped + map_len;

	// Create a block for the pages, merging with any adjacent blocks
	return _valloc_create_block(mapped, map_len);
}

static void *_valloc_new(size_t len) {
	// Get the biggest block
	treap_t *node = treap_peek();

	if (!node || node->len < len) {
		// Not enough space in that block, allocate more pages
		node = _valloc_map(len);
		if (!node) return NULL;
	} else {
		node = treap_pop();
	}

	// We have enough space in this block; split it in half and return the memory
	return _valloc_split_block(node, len);
}

// We do not currently free pages when they are empty.
// Instead, we release them back into the allocation pool so they can be reused.
static void _valloc_del(void *mem, size_t len) {
	_valloc_add_block(mem, len);
}

static void *_valloc_resize(void *mem, size_t old_len, size_t new_len) {
	ssize_t offset = new_len - old_len;

	// If the size isn't changing then... well... why?
	if (offset == 0) return mem;

	// If we're shrinking, simply release some memory back to the pool
	if (offset < 0) {
		_valloc_add_block(mem, -offset);
		return mem;
	}

	// First, try to resize it in-place
	// Check if there's a big enough adjacent block
	void *memend = (char *)mem + old_len;
	treap_t **right = treap_search_start(memend);
	if (right && (*right)->len >= offset) {
		// There is, so use it
		treap_t *tmp = *right;
		treap_remove(right);
		_valloc_add_block((char *)tmp + offset, tmp->len - offset);
		return mem;
	}

	// Now check if there's enough space in the pool already to allocate a new buffer to copy into
	treap_t *node = treap_peek();
	if (!node || node->len < new_len) {
		// Not enough space; allocate more pages
		node = _valloc_map(new_len);
		if (!node) return NULL;

		// There's a chance the new pages have been mapped next to the old block
		// Try to resize in-place again
		if (node == memend) {
			_valloc_add_block((char *)node + offset, node->len - offset);
			return mem;
		}
	} else {
		node = treap_pop();
	}

	// Allocate the memory and copy the old data
	void *new_mem = _valloc_split_block(node, new_len);
	memcpy(new_mem, mem, old_len);

	// Free the old memory
	_valloc_add_block(mem, old_len);

	return new_mem;
}
// }}}

// Public interface {{{
struct alloc_header {
	size_t len;
};

void *valloc(void *mem, size_t len) {
	// Get the header
	struct alloc_header *hdr = mem;
	hdr--;

	if (!len) {
		if (!mem) return NULL;
		// Free mem
		_valloc_del(hdr, hdr->len);
		return NULL;
	}

	// We're gonna be allocating or resizing, so adjust the length to include the header
	len += sizeof *hdr;

	if (!mem) {
		// Allocate
		hdr = _valloc_new(len);
	} else {
		// Resize
		hdr = _valloc_resize(hdr, hdr->len, len);
	}

	if (!hdr) return NULL;
	hdr->len = len;
	return hdr+1;
}

void *vallocz(void *mem, size_t len) {
	mem = valloc(mem, len);
	if (mem) {
		memset(mem, 0, len);
	}
	return mem;
}

void *valloca(void *mem, size_t len, size_t count) {
	size_t fulllen = len * count;
	if (len && count && fulllen / count != len) {
		_valloc_error();
	}
	return valloc(mem, fulllen);
}

void *vallocaz(void *mem, size_t len, size_t count) {
	size_t fulllen = len * count;
	if (len && count && fulllen / count != len) {
		_valloc_error();
	}
	return vallocz(mem, fulllen);
}

size_t vallocl(void *mem) {
	struct alloc_header *hdr = mem;
	hdr--;
	return hdr->len - sizeof *hdr;
}
// }}}
