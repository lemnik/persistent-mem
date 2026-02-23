//
// Created by Jason Morris on 30/07/2025.
//

#include "persistent_mem.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC_NUMBER   0x0000ADFBCADE
#define MIN_BLOCK_SIZE 32
#define MAX_BLOCK_SIZE 16777216
#define ALIGNMENT      16

// Free flag in block header
#define BLOCK_FREE    0x1

// Large block limit adjusted for architecture
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu

#define SIZE_MASK         0x7FFFFFFFFFFFFFFFuLL
#define FLAG_SHIFT        63

#else

#define SIZE_MASK         0x7FFFFFFFu
#define FLAG_SHIFT        31

#endif

// Utility functions
static inline size_t get_size(size_t size_and_flags) {
  return size_and_flags & SIZE_MASK;
}

static inline size_t get_flags(size_t size_and_flags) {
  return (size_and_flags >> FLAG_SHIFT) & 0x3;
}

static inline size_t make_size_and_flags(size_t size, size_t flags) {
  return (size & SIZE_MASK) | ((flags & 0x3) << FLAG_SHIFT);
}

static inline size_t align_up(size_t size, size_t alignment) {
  return (size + alignment - 1) & ~(alignment - 1);
}

static inline int size_to_class(size_t size) {
  if (size <= MIN_BLOCK_SIZE)
    return 0;
  if (size > MAX_BLOCK_SIZE)
    return -1;

#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu
  // 64-bit: Find MSB of (size - 1), then add 1 to round up
  int msb = 64 - __builtin_clzll(size - 1);
#else
  // 32-bit
  int msb = 32 - __builtin_clz((uint32_t)(size - 1));
#endif

  // Size class = msb - 5 (since 2^5 = 32 is class 0)
  return msb - 5;
}

static inline size_t class_to_size(int memclass) {
  static const size_t sizes[] = {
      32,     64,      128,     256,     512,     1024,    2048,
      4096,   8192,    16384,   32768,   65536,   131072,  262144,
      524288, 1048576, 2097152, 4194304, 8388608, MAX_BLOCK_SIZE
  };

  return (memclass >= 0 && memclass < MAX_SIZE_CLASS) ? sizes[memclass] : 0;
}

static block_header_t *get_next_contiguous_block(
        allocator_space_t *space, block_header_t *block) {

  const size_t heap_end = atomic_load(&space->heap_end);
  const uintptr_t heap_extent = (uintptr_t) space + heap_end;
  const uintptr_t address_of_next = (uintptr_t) block +
          sizeof(block_header_t) +
          get_size(block->size_and_flags);

  if (address_of_next >= heap_extent) {
    return NULL;
  }

  return (block_header_t *)address_of_next;
}

static inline bool is_persistent_ptr(allocator_space_t *space, void *ptr) {
  return (char *)ptr > (char *)space + space->heap_start && (char *)ptr < (char *)space + space->total_size;
}

/**
 * Init the allocator into the given space. This function will not re-init an
 * existing allocator into the space if one has already been initialized, making
 * this safe to call on allocator spaces that were previously mapped by other
 * processes (ie: archaeological allocator spaces).
 *
 * @param space the state to init
 * @param total_size the number of bytes allocated for the entire space (incl
 * the `allocator_state` structure)
 * @return 0 on success, -1 on failure
 */
static int init_allocator_state(allocator_space_t *space, size_t total_size) {
  uint32_t expected_magic = 0;
  if (!atomic_compare_exchange_strong(&space->magic, &expected_magic, MAGIC_NUMBER)) {
    return (atomic_load(&space->magic) == MAGIC_NUMBER) ? 0 : -1;
  }

  space->origin = (uintptr_t)space;
  space->total_size = total_size;
  space->heap_start = sizeof(allocator_space_t);
  atomic_store(&space->heap_end, sizeof(allocator_space_t));
  atomic_store(&space->roots_head, 0);

  for (int i = 0; i < MAX_SIZE_CLASS; i++) {
    atomic_store(&space->free_lists[i].free_head, 0);
  }

  return 0;
}

static inline bool block_try_set_flag(block_header_t *block, size_t flag) {
  size_t old_saf, new_saf;
  old_saf = atomic_load(&block->size_and_flags);
  do {
    if ((get_flags(old_saf) & flag) != 0) {
      return false;
    }

    new_saf = make_size_and_flags(get_size(old_saf), get_flags(old_saf) | flag);
  } while (!atomic_compare_exchange_weak(&block->size_and_flags, &old_saf, new_saf));

  return true;
}

static inline bool block_try_clear_flag(block_header_t *block, size_t flag) {
  size_t old_saf, new_saf;
  size_t flag_mask = ~flag;
  old_saf = atomic_load(&block->size_and_flags);
  do {
    // is the flag already cleared? if so we failed and return false
    if ((get_flags(old_saf) & flag) == 0) {
      return false;
    }

    new_saf = make_size_and_flags(get_size(old_saf), get_flags(old_saf) & flag_mask);
  } while (!atomic_compare_exchange_weak(&block->size_and_flags, &old_saf, new_saf));

  return true;
}

// Allocate a new block from the heap
static block_header_t *allocate_from_heap(allocator_space_t *space,
                                          size_t size) {
  size_t total_size = space->total_size;
  size_t current_end, new_end;

  current_end = atomic_load(&space->heap_end);
  do {
    new_end = current_end + sizeof(block_header_t) + size;

    if (new_end > total_size) {
      return NULL; // Out of memory :(
    }
  } while (!atomic_compare_exchange_weak(&space->heap_end, &current_end, new_end));

  block_header_t *block = (block_header_t *)((char *)space + current_end);
  atomic_store(&block->size_and_flags, make_size_and_flags(size, 0));
  atomic_store(&block->next_free, 0);

  return block;
}

// Split a block if it's large enough, returning the "remainder" if the block was split or
// NULL if the block was not large enough to split
static block_header_t *split_block(block_header_t *block,
                                   size_t needed_size) {
  size_t size_and_flags = atomic_load(&block->size_and_flags);
  size_t block_size = get_size(size_and_flags);

  if (block_size >= needed_size + sizeof(block_header_t) + MIN_BLOCK_SIZE) {
    // Split the block
    size_t remaining_size = block_size - needed_size - sizeof(block_header_t);
    block_header_t *new_block =
        (block_header_t *)((char *)block + sizeof(block_header_t) + needed_size);

    atomic_store(&new_block->size_and_flags,
                 make_size_and_flags(remaining_size, BLOCK_FREE));
    atomic_store(&new_block->next_free, 0);
    atomic_store(&block->size_and_flags, make_size_and_flags(needed_size, 0));

    return new_block;
  }

  return NULL;
}

static void free_list_push(allocator_space_t *space, free_list_t *lst,
                           block_header_t *block) {

  persistent_offset_t block_offset = ptr_to_persistent_offset(space, block);
  persistent_offset_t old_head_offset;

  old_head_offset = atomic_load(&lst->free_head);
  do {
    atomic_store(&block->next_free, old_head_offset);
  } while (!atomic_compare_exchange_weak(&lst->free_head, &old_head_offset,
          block_offset));
}

// Add block to appropriate free list
static void add_to_free_list(allocator_space_t *space, block_header_t *block) {
  // Mark as free
  if (!block_try_set_flag(block, BLOCK_FREE)) {
    // multi-threaded `free` for the same block, so we exit here
    return;
  }

  size_t size_and_flags = atomic_load(&block->size_and_flags);
  size_t size = get_size(size_and_flags);
  const int memclass = size_to_class(size);

  free_list_t *lst = &space->free_lists[memclass];
  free_list_push(space, lst, block);
}

static block_header_t *free_list_pop(allocator_space_t *space,
                                     free_list_t *lst) {

  persistent_offset_t head_offset, next_offset;

  do {
    head_offset = atomic_load(&lst->free_head);
    block_header_t *head = persistent_offset_to_ptr(space, head_offset);
    if (!head)
      return NULL;

    // Validate that head points to memory within the allocator space
    if (!is_persistent_ptr(space, head)) {
      return NULL;
    }

    // Read next_free while block is still in the list
    next_offset = atomic_load(&head->next_free);

    if (next_offset != 0) {
      block_header_t *next = persistent_offset_to_ptr(space, next_offset);
      if (!next || !is_persistent_ptr(space, next)) {
        return NULL;  // Invalid next pointer
      }
    }

    // Try to remove from the list
    if (atomic_compare_exchange_weak(&lst->free_head, &head_offset,
            next_offset)) {
      // Successfully removed - NOW mark as allocated (and not before!)
      if (block_try_clear_flag(head, BLOCK_FREE)) {
        atomic_store(&head->next_free, 0);
        return head;
      }
    }
    // CAS failed, head_offset updated, retry!
  } while (1);
}

// Remove block from free list
static block_header_t *remove_from_free_list(allocator_space_t *space,
                                             int memclass) {
  if (memclass < 0 || memclass >= MAX_SIZE_CLASS) {
    return NULL;
  }

  free_list_t *lst = &space->free_lists[memclass];
  return free_list_pop(space, lst);
}

// Restore a thread-local drained list back to the free list
static inline void restore_drained_list(allocator_space_t *space,
        block_header_t *drained_lst) {
  while (drained_lst) {
    block_header_t *restore = drained_lst;
    // Read next pointer BEFORE add_to_free_list overwrites it
    persistent_offset_t next_as_ptr = atomic_load(&restore->next_free);
    block_header_t *next_drained = (block_header_t *)next_as_ptr;
    drained_lst = next_drained;
    add_to_free_list(space, restore);
  }
}

// Attempt to merge this block with its next contiguous block if it is free
static bool try_merge_block_with_next(
        allocator_space_t *space,
        block_header_t *block) {
  block_header_t *next = get_next_contiguous_block(space, block);

  if (!next) {
    // There is no "next" block within the defined space, so we can't merge
    return false;
  }

  size_t next_size_and_flags = atomic_load(&next->size_and_flags);

  // Check if next block is free before attempting to claim it
  if (!(get_flags(next_size_and_flags) & BLOCK_FREE)) {
    // Next block is not free, cannot merge
    return false;
  }

  // Try to claim the next block by clearing its FREE flag
  // This prevents other threads from allocating it while we work
  if (!block_try_clear_flag(next, BLOCK_FREE)) {
    // Another thread already claimed or allocated this block
    return false;
  }

  // At this point we "own" the next block - it's marked as allocated
  // but hasn't been given to any user yet. We need to remove it from
  // its free list to complete the merge.

  // Get the size class for the next block
  size_t next_size = get_size(atomic_load(&next->size_and_flags));
  const int next_block_class = size_to_class(next_size);

  if (next_block_class < 0 || next_block_class >= MAX_SIZE_CLASS) {
    // Invalid size class - this shouldn't happen but handle it defensively
    // Re-mark the block as free since we're aborting
    block_try_set_flag(next, BLOCK_FREE);
    return false;
  }

  free_list_t *lst = &space->free_lists[next_block_class];

  // We need to remove 'next' from its free list using the drain-and-restore pattern
  // This is lock-free and handles all race conditions correctly
  block_header_t *drained_lst = NULL;

  for (;;) {
    block_header_t *b = free_list_pop(space, lst);

    if (b) {
      if (b == next) {
        // Found it! The block is now fully removed from the free list
        break;
      } else {
        // This is not our block, so we add it to our private list for later
        atomic_store(&b->next_free, (persistent_offset_t)drained_lst);
        drained_lst = b;
      }
    } else {
      // We've drained the entire free list without finding our block
      // This means another thread already removed it from the list (race condition)
      // BUT we still own the block (we cleared its FREE flag), so we can proceed
      // with the merge.
      break;
    }
  }

  // At this point, 'next' is fully owned by us (either found and removed, or already
  // removed by another thread but we still have ownership via the cleared FREE flag)
  // If we found it in the list, restore all drained blocks
  if (drained_lst) {
    restore_drained_list(space, drained_lst);
  }

  // Now we can safely merge the blocks
  // Calculate the new size: current block size + header + next block size
  size_t current_size_and_flags = atomic_load(&block->size_and_flags);
  size_t current_size = get_size(current_size_and_flags);
  size_t merged_size = current_size + sizeof(block_header_t) + next_size;

  // Update the current block's size to include the merged block
  // Preserve the current flags (the block should not be FREE if we're merging into it)
  size_t current_flags = get_flags(current_size_and_flags);
  atomic_store(&block->size_and_flags, make_size_and_flags(merged_size, current_flags));

  return true;
}

void *persistent_malloc(allocator_space_t *space, size_t size) {
  if (space == NULL || size == 0) {
    return NULL;
  }

  if (atomic_load(&space->magic) != MAGIC_NUMBER) {
    return NULL;
  }

  size_t aligned_size = align_up(size, ALIGNMENT);
  int memclass = size_to_class(aligned_size);
  block_header_t *block = NULL;

  if (memclass >= 0) {
    // Try to get from free list first
    block = remove_from_free_list(space, memclass);
    if (block) {
      // We found a block. See if it's big enough to split.
      block_header_t *remainder = split_block(block, aligned_size);
      if (remainder) {
        // A new smaller block was split off. Add it to the correct free list.
        add_to_free_list(space, remainder);
      }
      // Return the original block (now correctly sized) to the user.
      return (char *)block + sizeof(block_header_t);
    }

    // If free list was empty, allocate a new block of the exact size class.
    size_t class_size = class_to_size(memclass);
    block = allocate_from_heap(space, class_size);
    if (block) {
      // We just allocated a fresh block. It might be larger than needed.
      block_header_t *remainder = split_block(block, aligned_size);
      if (remainder) {
        // Add the leftover piece to the free list.
        add_to_free_list(space, remainder);
      }
      return (char *)block + sizeof(block_header_t);
    }
  }

  return NULL;
}

void persistent_free(allocator_space_t *space, void *ptr) {
  if (!space || !ptr)
    return;

  if (atomic_load(&space->magic) != MAGIC_NUMBER) {
    return;
  }

  block_header_t *block =
      (block_header_t *)((char *)ptr - sizeof(block_header_t));

  // Validate block is within our region
  if (!is_persistent_ptr(space, block)) {
    return;
  }

  size_t size_and_flags = atomic_load(&block->size_and_flags);
  if (get_flags(size_and_flags) & BLOCK_FREE) {
    return; // Double free protection
  }

  // we attempt to coalesce this block with its contiguous "next" to reduce
  // fragmentation, we spin this until it no longer succeeds
  while (try_merge_block_with_next(space, block));

  add_to_free_list(space, block);
}

void *persistent_realloc(allocator_space_t *space, void *ptr, size_t new_size) {
  if (!space)
    return NULL;

  if (atomic_load(&space->magic) != MAGIC_NUMBER) {
    return NULL;
  }

  if (!ptr) {
    return persistent_malloc(space, new_size);
  }

  if (new_size == 0) {
    persistent_free(space, ptr);
    return NULL;
  }

  block_header_t *block = (block_header_t *)((char *)ptr - sizeof(block_header_t));
  size_t size_and_flags = atomic_load(&block->size_and_flags);
  size_t old_size = get_size(size_and_flags);
  size_t aligned_new_size = align_up(new_size, ALIGNMENT);

  if (aligned_new_size <= old_size) {
    // shrinking or the same size, split_block handles the distinction for us already
    block_header_t *remainder = split_block(block, aligned_new_size);
    if (remainder) {
      add_to_free_list(space, remainder);
    }
    return ptr;
  }

  // Can we merge this block with the next block to achieve the desired size
  block_header_t *next = get_next_contiguous_block(space, block);
  if (next) {
    int size_and_flags = atomic_load(&next->size_and_flags);
    size_t next_size = get_size(size_and_flags);

    // the block is free, so we should check whether the combined size if enough
    if (get_flags(size_and_flags) & BLOCK_FREE) {
      size_t combined_size = old_size + sizeof(block_header_t) + next_size;

      if (aligned_new_size <= combined_size &&
        try_merge_block_with_next(space, block)) {

        // the block was successfully merged with next
        return ptr;
      }
    }
  }

  // Need to allocate new block
  void *new_ptr = persistent_malloc(space, new_size);
  if (!new_ptr) {
    return NULL;
  }

  // Copy old data
  memcpy(new_ptr, ptr, old_size);
  persistent_free(space, ptr);

  return new_ptr;
}


allocator_space_t *load_private_persistent_allocator(const char *filename) {
  struct stat st;
  if (stat(filename, &st) != 0) {
    return NULL;
  }

  const size_t size = st.st_size;

  int fd = open(filename, O_RDWR, 0);
  if (fd < 0) {
    return NULL;
  }

  void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  // we don't need the fd anymore, so we can close it
  close(fd);

  if (mapped == MAP_FAILED) {
    return NULL;
  }

  allocator_space_t *space = (allocator_space_t *)mapped;
  if (atomic_load(&space->magic) != MAGIC_NUMBER) {
    munmap(space, size);
    return NULL;
  }

  return space;
}

allocator_space_t *create_persistent_allocator(const char *filename,
                                               const size_t requested_size) {
  size_t size = requested_size;
  if (size < sizeof(allocator_space_t) + 4096) {
    size = sizeof(allocator_space_t) + 4096; // Minimum size
  }

  // On 32-bit systems, ensure we don't exceed addressable space
  if (size > SIZE_MAX) {
    return NULL;
  }

  int fd = open(filename, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return NULL;
  }

  // Extend file to desired size
  if (ftruncate(fd, (off_t)size) < 0) {
    close(fd);
    return NULL;
  }

  void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  // we don't need the fd anymore, so we can close it
  close(fd);

  if (mapped == MAP_FAILED) {
    return NULL;
  }

  allocator_space_t *state = (allocator_space_t *)mapped;
  if (init_allocator_state(state, size) != 0) {
    munmap(mapped, size);
    return NULL;
  }

  return state;
}

void *persistent_malloc_root(allocator_space_t *space, uint64_t root_class,
                             size_t size) {
  allocator_root_t *new_root = persistent_malloc(space, sizeof(allocator_root_t) + size);
  if (!new_root) {
    return NULL;
  }

  new_root->root_class = root_class;
  persistent_offset_t current_first_root_offset = atomic_load(&space->roots_head);
  persistent_offset_t new_root_offset = ptr_to_persistent_offset(space, new_root);
  for (;;) {
    atomic_store(&new_root->next_root, current_first_root_offset);

    if (atomic_compare_exchange_weak(
            &space->roots_head, &current_first_root_offset, new_root_offset)) {
      return &new_root->content;
    }
  }
}

void *persistent_find_root(allocator_space_t *space, uint64_t root_class) {
  if (!space) {
    return NULL;
  }

  persistent_offset_t root_offset = atomic_load(&space->roots_head);
  while (root_offset) {
    allocator_root_t *root = persistent_offset_to_ptr(space, root_offset);
    if (root->root_class == root_class) {
      return &root->content;
    }

    root_offset = atomic_load(&root->next_root);
  }

  return NULL;
}

void *persistent_ptr(allocator_space_t *space, void *ptr) {
  if (space == NULL || ptr == NULL) {
    return NULL;
  }

  const size_t original_origin = space->origin;
  const size_t current_origin = (uintptr_t)space;

  // If the mapping hasn't changed, the pointer is already valid.
  if (original_origin == current_origin) {
    return ptr;
  }

  // Calculate the offset of the pointer from the original base address.
  const size_t offset = (uintptr_t)ptr - original_origin;

  const size_t heap_start_offset = space->heap_start;
  const size_t heap_end_offset = atomic_load(&space->heap_end);

  // Validate that the offset falls within the heap boundaries.
  if (offset < heap_start_offset || offset >= heap_end_offset) {
    return NULL;
  }

  // Rebase the pointer to the current mapping.
  return (void *)(current_origin + offset);
}

void destroy_persistent_allocator(allocator_space_t *space) {
  if (space && atomic_load(&space->magic) == MAGIC_NUMBER) {
    munmap(space, space->total_size);
  }
}
