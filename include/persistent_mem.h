//
// Created by Jason Morris on 30/07/2025.
//

#ifndef PERSISTENT_MEM_H
#define PERSISTENT_MEM_H


#ifdef __cplusplus
#include <atomic>
#define ATOMIC(T) std::atomic<T>
#else
#include <stdatomic.h>
#define ATOMIC(T) _Atomic(T)
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef PERSISTENT_MEM_LOG
#define PERSISTENT_MEM_LOG(fmt, ...) ((void)0)
// #define PERSISTENT_MEM_LOG(fmt, ...) printf("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
// #define PERSISTENT_MEM_LOG(fmt, ...) __android_log_print(ANDROID_LOG_FATAL, "PersistentMem", "[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define MAX_SIZE_CLASS 20

#ifdef __cplusplus
extern "C" {
#endif

// special name for offsets within the persistent space
typedef uint64_t persistent_offset_t;

#define ptr_to_persistent_offset(space, ptr) ((uint64_t)ptr > (uint64_t)space ? (uint64_t)ptr - (uint64_t)space : 0)
#define persistent_offset_to_ptr(space, offset) (offset != 0 ? (void*)((uint64_t)space + offset) : 0)

// Block header - stored before each allocated block
typedef struct block_header {
    // size in lower 60 bits, flags in upper 4 bits
    ATOMIC(uint64_t) size_and_flags;
    // next in free list (only used when free)
    ATOMIC(persistent_offset_t) next_free;
} block_header_t;

// Size memclass for segregated free lists
typedef struct size_class {
    // head of free list for this size class
    ATOMIC(persistent_offset_t) free_head;
} size_class_t;

/**
 * Persistent allocator space stored within the persistent (file-backed) region. The `origin` is
 * set to `&allocator_space` when the file is first created, allowing the file to be mapped again
 * later into a different address and for [persistent_ptr] to rewrite the addresses to remain valid.
 */
typedef struct allocator_space {
    ATOMIC(uint32_t) magic;                   // magic number for validation
    ATOMIC(uint64_t) origin;                  // the base pointer of the mmap region
    ATOMIC(uint64_t) total_size;              // total size of mmap region
    ATOMIC(uint64_t) heap_start;              // offset to start of heap area
    ATOMIC(uint64_t) heap_end;                // current end of heap
    size_class_t size_classes[MAX_SIZE_CLASS];  // segregated free lists
    ATOMIC(uint64_t) large_free_head;         // offset to large block free list
    ATOMIC(persistent_offset_t) roots_head;
} allocator_space_t;

/**
 * Roots are special allocations that can be rediscovered when loading persistent memory from a
 * previous process. See [persistent_malloc_root] and [persistent_find_root].
 */
typedef struct allocator_root {
    uint64_t root_class;
    ATOMIC(persistent_offset_t) next_root;
    char content;
} allocator_root_t;

/**
 * Create a fixed-size persistent sub-heap within filename of size bytes. The memory region cannot
 * be shrunk or grown.
 *
 * @param filename
 * @param requested_size
 * @return
 */
allocator_space_t *create_persistent_allocator(const char *filename, size_t requested_size);

void *persistent_malloc(allocator_space_t *space, size_t size);

/**
 * Allocate a "root" for the given allocator. Roots are special regions tagged with a "root class"
 * value that can indicate something about what is stored there. They can be iterated over directly
 * from the `allocator_space` but *cannot* be freed or resized. Most regions will only ever have a
 * single root as a way to "re-enter" the structures stored after the allocator has been closed
 * and re-opened.
 *
 * Roots can be identified and retrieved later using their `root_class` using
 * [persistent_find_root].
 *
 * @param space the space to allocate the root in
 * @param root_class the identifier for the new root
 * @param size the number of bytes to allocate for the new root
 * @return a pointer to at least [size] bytes of persistent memory, or NULL if the allocation failed
 */
void *
persistent_malloc_root(allocator_space_t *space, uint64_t root_class, size_t size);

/**
 * Attempts to find a specific root within `space`.
 *
 * @param space the allocator to search
 * @param root_class the identifier for the root to find
 * @return a pointer to the selected root or NULL if it cannot be found in `space`.
 */
void *
persistent_find_root(allocator_space_t *space, uint64_t root_class);

void persistent_free(allocator_space_t *space, void *ptr);

/**
 * Returns the correct "current" value of [ptr] for [space] where `ptr` is a pointer stored within
 * the given `space`, but where `space` potentially had a different address when `ptr` was
 * established. That is: `space` might represent a memory snapshot from another process or from
 * a previous run, `ptr` was once a valid pointer but is now likely invalid. This function either
 * corrects the address, or returns `NULL` if the pointer address is outside of the `space` space.
 *
 * @param space
 * @param ptr
 * @return
 */
void *persistent_ptr(allocator_space_t *space, void *ptr);

void *persistent_realloc(allocator_space_t *space, void *ptr, size_t new_size);

void destroy_persistent_allocator(allocator_space_t *space);

#ifdef __cplusplus
}
#endif
#endif //PERSISTENT_MEM_H
