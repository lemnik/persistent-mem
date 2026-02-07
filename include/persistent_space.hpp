#ifdef __cplusplus

#pragma once

#include "persistent_mem.h"
#include <cstddef>

namespace persistent_mem {

/**
 * A relocatable handle to a persistent memory allocator space.
 *
 * PersistentSpace stores a relative offset to an allocator_space_t rather than
 * a raw pointer, allowing it to remain valid even if the underlying
 * memory-mapped file is remapped to a different virtual address. This makes it
 * useful within the persistent memory region itself, allowing "persistent"
 * classes to easily retain a reference to their allocator space.
 *
 * The class provides a C++ wrapper around the persistent_mem.h allocator with
 * automatic type safety and constructor/destructor support.
 */
class PersistentSpace {
public:
    PersistentSpace(allocator_space_t *space) noexcept {
        space_offset_ = space_offset_for(this, space);
    }

    ~PersistentSpace() noexcept {}

    // Copy constructor
    PersistentSpace(const PersistentSpace &other) noexcept {
        space_offset_ = space_offset_for(this, other.unwrap());
    }

    // Move constructor
    PersistentSpace(const PersistentSpace &&other) noexcept {
        space_offset_ = space_offset_for(this, other.unwrap());
    }

    // Assignment operators
    PersistentSpace &operator=(const PersistentSpace &other) noexcept {
        if (this != &other) {
            allocator_space_t *space = other.unwrap();
            space_offset_ = space_offset_for(this, space);
        }
        return *this;
    }

    // Assignment from nullptr
    PersistentSpace &operator=(decltype(nullptr)) noexcept {
        space_offset_ = 0;
        return *this;
    }

    // Boolean conversion
    explicit operator bool() const noexcept { return space_offset_ != 0; }

    allocator_space_t *unwrap() const noexcept {
        if (space_offset_ == 0) {
            return nullptr;
        }
        uintptr_t this_addr = reinterpret_cast<uintptr_t>(this);
        return reinterpret_cast<allocator_space_t *>(this_addr + space_offset_);
    }


    template<typename T>
    T* find_root(uint64_t root_class) noexcept {
        auto space = unwrap();
        if (!space) {
            return nullptr;
        }

        return static_cast<T*>(persistent_find_root(space, root_class));
    }

    template<typename T, typename... Args>
    T* alloc(Args&&... args) noexcept {
        auto space = unwrap();
        if (!space) {
            return nullptr;
        }

        T *v = static_cast<T*>(persistent_malloc(space, sizeof(T)));
        if (v) {
            new(v) T(std::forward<Args>(args)...);
        }
        return v;
    }

    template<typename T, typename... Args>
    T* alloc_root(const uint64_t root_class, Args&&... args) noexcept {
        auto space = unwrap();
        if (!space) {
            return nullptr;
        }

        T *v = static_cast<T*>(persistent_malloc_root(space, root_class, sizeof(T)));
        if (v) {
            new(v) T(std::forward<Args>(args)...);
        }
        return v;
    }

    template<typename T>
    T* alloc(const std::size_t count) noexcept {
        auto space = unwrap();
        if (!space) {
            return nullptr;
        }

        T *v = static_cast<T*>(persistent_malloc(space, sizeof(T) * count));
        return v;
    }

    template<typename T>
    void free(T* value) noexcept {
        auto space = unwrap();
        if (space) {
            persistent_free(space, value);
        }
    }

    template<typename T>
    T *restore(T *original) noexcept {
        auto space = unwrap();
        if (space) {
            return persistent_ptr(space, original);
        }
        return nullptr;
    }

private:
    // Offset from this pointer's address to the allocator_space_t
    // This is signed because space could be before or after this pointer (if the
    // PersistentSpace is placed outside of its allocator_space)
    ptrdiff_t space_offset_;

    static ptrdiff_t space_offset_for(PersistentSpace *_this, allocator_space_t *space) {
        if (space) {
            uintptr_t this_addr = reinterpret_cast<uintptr_t>(_this);
            uintptr_t space_addr = reinterpret_cast<uintptr_t>(space);
            return space_addr - this_addr;
        } else {
            return 0;
        }
    }
};

}

#endif
