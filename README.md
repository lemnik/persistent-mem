# Persistence of Memory

A pure C (though C++ compatible) allocator that works with `mmap` allowing you to retain data semi-transparently between process runs. This allows you to "run" within a persistent space without the typical overheads of file I/O, and for your memory structures to be recovered, either to continue running or to "archeologically" retrieve data from before a crash (depending on your needs and architecture).

## Features

- ***thread safe && lock free*** - no blocking, no spin locks, just pure atomics
- `malloc`, `free` and `realloc` implementations
- ***archeology / forensic capabilities*** - rewrite pointers from previous memory spaces using `persistent_ptr`
- ***identifiable / tagged allocations*** - `persistent_malloc_root` allows "root" allocations to be tagged for later retrieval (between process runs)
- ***some C++ functionality*** - smart/fancy pointer named `PersistentPtr<*>` automatically keeps track of its `allocator_space` even between address changes (restarts)
  - `PersistentPtr` is header-only and `nostdlib` compatible

## Limitations

- Fixed size - the allocator currently works strictly within a single fixed region and will not attempt to acquire more memory
- No `calloc` equivilent - if you want clean memory, use `memset` after `persistent_malloc`
- Non-optimal realloc - `persistent_realloc` will not attempt to merge contiguous blocks of memory
- `PersistentPtr` cannot be made atomic (yet) - this will be added when I have time
- No C++ STL `Allocator`

### Pointer considerations
Care needs to be taken when using raw pointers within the space, `persistent_ptr` can be used to archeologically recover raw pointers from a previous run, but you should treat these spaces as __read only__. `persistent_ptr` works by adjusting the pointer based on the "old" and "new" memory address of the persistent space (`new_raw_ptr = old_raw_ptr - &old_raw + &new_space`) but since there is only a single slot for the `origin` to be stored we can only adjust from a single "old" space into our "new" space. For more flexibility C code can make use of the `persistent_offset_t` typealias along with the `ptr_to_persistent_offset` and `persistent_persistent_offset_to_ptr` macros to convert to and from raw pointers.

For C++ code there is a `persistent_mem::PersistentPtr` template class which can be treated like other fancy pointers, but remain internally consistent if they are properly initialised (they *must* be passed a `allocator_space_t*` at least once).
