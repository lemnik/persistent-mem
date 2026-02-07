# Implementation Details & Notes

The allocator is a relatively simple block based allocator. Each allocated block typically belongs to a "memory class" which determines the amount of memory it consumes. Within each block header we keep track of its size (which determines its memclass) along with a space for the next free block (when it is on the free list).

## Core Principals

### Blocks

All memory from this allocator come in the form of "blocks" of fixed sizes (each size group is called a memory class or `memclass`). As such most allocations are typically slightly larger than the requested number of bytes (the minimum block size being 32 bytes). This allows relatively efficient expansion in `persistent_realloc` by "just" marking the block as being larger. As such: every allocation has 2 sizes: the requested (public) size and the actual (block) size (the block header also takes some space, but that's not important here).

### Offsets vs Pointers

Within the `allocator_space` all the pointers are replaced by offsets against the start of the space. This allows the space to be stored and restored without needing to rewrite the pointers directly. The `persistent_offset_to_ptr` macro is used extensively throughout the implementation so that this detail is hidden from code using the allocator.

This offset behaviour can become unintuitive when dealing with our atomic lists where we need to flip back and forth between the offset (as the value of `next`) and the raw pointer value (as the address being set).

### Lock-free linked lists

All the link lists in the allocator are effectively single linked *stacks*. They are not iterated over (except the roots), and the only operations used are "add" (push) and "remove" (pop). This keeps the number of possible race conditions to a minimum since removal cannot happen during traversal.

## Free lists

For each memory class (block size) we maintain a singly linked list of blocks that have been released with `persistent_free`.

Blocks are marked as being "free" by setting their "free" flag *strictly before* adding them to the list. This __helps__ defend against double-free bugs, but does not fully prevent them in a concurrent environment where you could have the sequence:

1. `threadA`: free is called for the block
1. `threadA`: mark as free
1. `threadA`: add to free list
1. `threadB`: take from free list
1. `threadB`: mark as in use (not free)
1. `threadA`: free is called again for the block
1. __the second invalid free succeeds here because `threadB` has cleared the "free" flag__
1. `threadB`: WAT

We don't currently guard against this behaviour as it is currently considered extremely unlikely and probably the result of buggy code.

### Block Coalescing / Merging

When a block is freed and the "next" contiguous block of memory is already free we will attempt to merge them together to form a single, larger block. This is done with a brute-force drain-and-restore of the appropriate free-list. This approach is simple and works using the other alloc/free primitives to avoid ABA and race conditions. While there are more optimal solutions to unlinking the block, actual coalescing is relatively rare as we first "steal" the neighbouring block by marking it as non-free (clearing its `FREE` flag) which ensures it cannot be allocated. If we cannot steal the block, then no coalescing can take place and the expensive drain-and-restore is completely skipped.

The algorithm does raise a possible memory starvation for the coalescing memclass while the list is being drained, but this is rare and will mostly result in other threads simply splitting a larger memclass or resorting to heap allocation.
