//
// Created by Jason Morris on 30/07/2025.
//

#include "persistent_mem.h"

#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAGIC_NUMBER 0x0000ADFBCADE
#define MIN_BLOCK_SIZE 32
#define ALIGNMENT 16

// Flags for block header
#define BLOCK_FREE 0x1
#define BLOCK_LARGE 0x2

// Utility functions
static inline uint64_t get_size(uint64_t size_and_flags) {
    return size_and_flags & 0x0FFFFFFFFFFFFFFFuLL;
}

static inline uint64_t get_flags(uint64_t size_and_flags) {
    return (size_and_flags >> 60) & 0xF;
}

static inline uint64_t make_size_and_flags(uint64_t size, uint64_t flags) {
    return (size & 0x0FFFFFFFFFFFFFFFULL) | ((flags & 0xF) << 60);
}

static inline uint64_t align_up(uint64_t size, uint64_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

static inline int size_to_class(uint64_t size) {
    if (size <= 32) return 0;
    if (size > 16777216) return -1;

    // Find MSB of (size - 1), then add 1 to round up
    int msb = 64 - __builtin_clzll(size - 1);

    // Size class = msb - 5 (since 2^5 = 32 is class 0)
    return msb - 5;
}

static inline uint64_t class_to_size(int memclass) {
    static const uint64_t sizes[] = {
            32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
            32768, 65536, 131072, 262144, 524288, 1048576, 2097152,
            4194304, 8388608, 16777216
    };
    return (memclass >= 0 && memclass < MAX_SIZE_CLASS) ? sizes[memclass] : 0;
}

/**
 * Init the allocator into the given space. This function will not re-init an existing allocator
 * into the space if one has already been initialized, making this safe to call on allocator spaces
 * that were previously mapped by other processes (ie: archaeological allocator spaces).
 *
 * @param space the state to init
 * @param total_size the number of bytes allocated for the entire space (incl the `allocator_state` structure)
 * @return 0 on success, -1 on failure
 */
static int init_allocator_state(allocator_space_t *space, uint64_t total_size) {
    uint32_t expected_magic = 0;
    if (!atomic_compare_exchange_strong(&space->magic, &expected_magic, MAGIC_NUMBER)) {
        return (atomic_load(&space->magic) == MAGIC_NUMBER) ? 0 : -1;
    }

    atomic_store(&space->origin, (uint64_t) space);
    atomic_store(&space->total_size, total_size);
    atomic_store(&space->heap_start, sizeof(allocator_space_t));
    atomic_store(&space->heap_end, sizeof(allocator_space_t));
    atomic_store(&space->large_free_head, 0);
    atomic_store(&space->roots_head, 0);

    for (int i = 0; i < MAX_SIZE_CLASS; i++) {
        atomic_store(&space->size_classes[i].free_head, 0);
    }

    return 0;
}

// Allocate a new block from the heap
static block_header_t *allocate_from_heap(allocator_space_t *space, uint64_t size) {
    uint64_t total_size = atomic_load(&space->total_size);
    uint64_t current_end, new_end;

    current_end = atomic_load(&space->heap_end);
    do {
        new_end = current_end + sizeof(block_header_t) + size;

        if (new_end > total_size) {
            return NULL; // Out of memory
        }
    } while (!atomic_compare_exchange_weak(&space->heap_end, &current_end, new_end));

    block_header_t *block = (block_header_t *) ((char *) space + current_end);
    atomic_store(&block->size_and_flags, make_size_and_flags(size, 0));
    atomic_store(&block->next_free, 0);

    return block;
}

// Split a block if it's large enough
static block_header_t *
split_block(block_header_t *block, uint64_t needed_size) {
    uint64_t size_and_flags = atomic_load(&block->size_and_flags);
    uint64_t block_size = get_size(size_and_flags);

    if (block_size >= needed_size + sizeof(block_header_t) + MIN_BLOCK_SIZE) {
        // Split the block
        uint64_t remaining_size = block_size - needed_size - sizeof(block_header_t);
        block_header_t *new_block = (block_header_t *) ((char *) block + sizeof(block_header_t) +
                                                        needed_size);

        atomic_store(&new_block->size_and_flags, make_size_and_flags(remaining_size, BLOCK_FREE));
        atomic_store(&new_block->next_free, 0);
        atomic_store(&block->size_and_flags, make_size_and_flags(needed_size, 0));

        return new_block;
    }

    return NULL;
}

// Add block to appropriate free list
static void add_to_free_list(allocator_space_t *space, block_header_t *block) {
    // Mark as free
    uint64_t old_saf, new_saf;
    old_saf = atomic_load(&block->size_and_flags);
    do {
        new_saf = make_size_and_flags(get_size(old_saf), get_flags(old_saf) | BLOCK_FREE);
    } while (!atomic_compare_exchange_weak(&block->size_and_flags, &old_saf, new_saf));

    uint64_t size_and_flags = atomic_load(&block->size_and_flags);
    uint64_t size = get_size(size_and_flags);
    const int memclass = size_to_class(size);

    if (memclass >= 0) {
        // Small/medium block - add to size memclass
        size_class_t *sc = &space->size_classes[memclass];
        persistent_offset_t block_offset = ptr_to_persistent_offset(space, block);
        persistent_offset_t old_head_offset;

        old_head_offset = atomic_load(&sc->free_head);
        do {
            atomic_store(&block->next_free, old_head_offset);
        } while (!atomic_compare_exchange_weak(&sc->free_head, &old_head_offset, block_offset));
    } else {
        // Large block - add to large free list
        uint64_t block_offset = (uint64_t)((char *) block - (char *) space);
        uint64_t old_head_offset;

        old_head_offset = atomic_load(&space->large_free_head);
        do {
            atomic_store(&block->next_free,
                         old_head_offset ? (persistent_offset_t) ((char *) space + old_head_offset)
                                         : 0);
        } while (!atomic_compare_exchange_weak(&space->large_free_head, &old_head_offset,
                                               block_offset));
    }
}

// Remove block from free list
static block_header_t *remove_from_free_list(allocator_space_t *space, int memclass) {
    if (memclass < 0 || memclass >= MAX_SIZE_CLASS) {
        return NULL;
    }

    size_class_t *sc = &space->size_classes[memclass];
    persistent_offset_t head_offset;

    do {
        head_offset = atomic_load(&sc->free_head);
        if (!head_offset) return NULL;

        block_header_t *head = persistent_offset_to_ptr(space, head_offset);

        persistent_offset_t next_offset = atomic_load(&head->next_free);
        if (atomic_compare_exchange_weak(&sc->free_head, &head_offset, next_offset)) {
            // Mark as allocated
            uint64_t old_saf, new_saf;
            old_saf = atomic_load(&head->size_and_flags);
            do {
                new_saf = make_size_and_flags(get_size(old_saf), get_flags(old_saf) & ~BLOCK_FREE);
            } while (!atomic_compare_exchange_weak(&head->size_and_flags, &old_saf, new_saf));

            atomic_store(&head->next_free, 0);
            return head;
        }
    } while (1);
}

void *persistent_malloc(allocator_space_t *space, size_t size) {
    if (!space || size == 0) return NULL;

    if (atomic_load(&space->magic) != MAGIC_NUMBER) {
        return NULL;
    }

    uint64_t aligned_size = align_up(size, ALIGNMENT);
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
            return (char *) block + sizeof(block_header_t);
        }

        // If free list was empty, allocate a new block of the exact size class.
        uint64_t class_size = class_to_size(memclass);
        block = allocate_from_heap(space, class_size);
        if (block) {
            // We just allocated a fresh block. It might be larger than needed.
            block_header_t *remainder = split_block(block, aligned_size);
            if (remainder) {
                // Add the leftover piece to the free list.
                add_to_free_list(space, remainder);
            }
            return (char *) block + sizeof(block_header_t);
        }
    } else {
        // Large allocation - allocate directly from heap
        block = allocate_from_heap(space, aligned_size);
        if (block) {
            // Mark as a large block
            uint64_t old_saf, new_saf;
            old_saf = atomic_load(&block->size_and_flags);
            do {
                new_saf = make_size_and_flags(get_size(old_saf), get_flags(old_saf) | BLOCK_LARGE);
            } while (!atomic_compare_exchange_weak(&block->size_and_flags, &old_saf, new_saf));

            return (char *) block + sizeof(block_header_t);
        }
    }

    return NULL;
}

void persistent_free(allocator_space_t *space, void *ptr) {
    if (!space || !ptr) return;

    if (atomic_load(&space->magic) != MAGIC_NUMBER) {
        return;
    }

    block_header_t *block = (block_header_t *) ((char *) ptr - sizeof(block_header_t));

    // Validate block is within our region
    if ((char *) block < (char *) space ||
        (char *) block >= (char *) space + atomic_load(&space->total_size)) {
        return;
    }

    uint64_t size_and_flags = atomic_load(&block->size_and_flags);
    if (get_flags(size_and_flags) & BLOCK_FREE) {
        return; // Double free protection
    }

    add_to_free_list(space, block);
}

void *persistent_realloc(allocator_space_t *space, void *ptr, size_t new_size) {
    if (!space) return NULL;

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

    block_header_t *block = (block_header_t *) ((char *) ptr - sizeof(block_header_t));
    uint64_t size_and_flags = atomic_load(&block->size_and_flags);
    uint64_t old_size = get_size(size_and_flags);
    uint64_t aligned_new_size = align_up(new_size, ALIGNMENT);

    if (aligned_new_size <= old_size) {
        // Shrinking or same size
        return ptr;
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

// Initialization function for the allocator
allocator_space_t *create_persistent_allocator(const char *filename, const size_t requested_size) {
    size_t size = requested_size;
    if (size < sizeof(allocator_space_t) + 4096) {
        size = sizeof(allocator_space_t) + 4096; // Minimum size
    }

    int fd = open(filename, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        return NULL;
    }

    // Extend file to desired size
    if (ftruncate(fd, (off_t) size) < 0) {
        close(fd);
        return NULL;
    }

    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // we don't need the fd anymore, so we can close it
    close(fd);

    if (mapped == MAP_FAILED) {
        return NULL;
    }

    allocator_space_t *state = (allocator_space_t *) mapped;
    if (init_allocator_state(state, size) != 0) {
        munmap(mapped, size);
        return NULL;
    }

    return state;
}

void *persistent_malloc_root(allocator_space_t *space, uint64_t root_class, size_t size) {
    allocator_root_t *new_root = persistent_malloc(space, sizeof(allocator_root_t) + size);
    if (!new_root) {
        return NULL;
    }

    new_root->root_class = root_class;
    persistent_offset_t current_first_root_offset = atomic_load(&space->roots_head);
    persistent_offset_t new_root_offset = ptr_to_persistent_offset(space, new_root);
    for (;;) {
        atomic_store(&new_root->next_root, current_first_root_offset);

        if (atomic_compare_exchange_weak(&space->roots_head, &current_first_root_offset, new_root_offset)) {
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

    const uint64_t original_origin = atomic_load(&space->origin);
    const uint64_t current_origin = (uint64_t) space;

    // If the mapping hasn't changed, the pointer is already valid.
    if (original_origin == current_origin) {
        return ptr;
    }

    // Calculate the offset of the pointer from the original base address.
    const uint64_t offset = (uint64_t) ptr - original_origin;

    const uint64_t heap_start_offset = atomic_load(&space->heap_start);
    const uint64_t heap_end_offset = atomic_load(&space->heap_end);

    // Validate that the offset falls within the heap boundaries.
    if (offset < heap_start_offset || offset >= heap_end_offset) {
        return NULL;
    }

    // Rebase the pointer to the current mapping.
    return (void *) (current_origin + offset);
}

void destroy_persistent_allocator(allocator_space_t *space) {
    if (space) {
        uint64_t total_size = atomic_load(&space->total_size);
        munmap(space, total_size);
    }
}
