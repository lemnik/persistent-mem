#ifdef __cplusplus

#pragma once

#include "persistent_mem.h"

namespace persistent_mem {

/**
 * Self-relative persistent pointer. Stores both the data offset AND the offset
 * to its allocator_space_t. Uses its own address (`this`) to calculate the
 * current space address. This is fully persistent-safe and requires no external
 * setup when used properly (make sure its memory is properly initialized).
 *
 * *Never* use this class with `new`.
 */
template <typename T> class PersistentPtr {
public:
  using element_type = T;
  using difference_type = ptrdiff_t;

  // Default constructor creates null pointer
  PersistentPtr(allocator_space_t *space) noexcept
      : PersistentPtr(nullptr, space) {}

  // Construct from raw pointer and space
  PersistentPtr(T *ptr, allocator_space_t *space) noexcept {
    if (ptr && space) {
      // Calculate offset from space origin to data
      uint64_t space_addr = reinterpret_cast<uint64_t>(space);
      data_offset_ = reinterpret_cast<uint64_t>(ptr) - space_addr;

      // Calculate offset from this pointer to space
      uint64_t this_addr = reinterpret_cast<uint64_t>(this);
      space_offset_ = space_addr - this_addr;
    } else {
      data_offset_ = 0;
      space_offset_ = 0;
    }
  }

  // Copy constructor
  PersistentPtr(const PersistentPtr &other) noexcept
      : data_offset_(other.data_offset_) {
    // We're technically a "new" pointer so the address of 'this != other.this'
    // we need to calculate our new offset from the allocator_space
    if (data_offset_ != 0) {
      allocator_space_t *space = other.get_space();
      if (space) {
        uint64_t this_addr = reinterpret_cast<uint64_t>(this);
        uint64_t space_addr = reinterpret_cast<uint64_t>(space);
        space_offset_ = space_addr - this_addr;
      } else {
        space_offset_ = 0;
      }
    } else {
      space_offset_ = 0;
    }
  }

  ~PersistentPtr() noexcept {}

  // Assignment operator
  PersistentPtr &operator=(const PersistentPtr &other) noexcept {
    if (this != &other) {
      data_offset_ = other.data_offset_;

      // Recalculate space_offset relative to OUR position
      if (data_offset_ != 0) {
        allocator_space_t *space = other.get_space();
        if (space) {
          uint64_t this_addr = reinterpret_cast<uint64_t>(this);
          uint64_t space_addr = reinterpret_cast<uint64_t>(space);
          space_offset_ = space_addr - this_addr;
        } else {
          space_offset_ = 0;
        }
      } else {
        space_offset_ = 0;
      }
    }
    return *this;
  }

  // Rebinding copy constructor
  template <typename U>
  PersistentPtr(const PersistentPtr<U> &other) noexcept
      : data_offset_(other.get_data_offset()) {
    if (data_offset_ != 0) {
      allocator_space_t *space = other.get_space();
      if (space) {
        uint64_t this_addr = reinterpret_cast<uint64_t>(this);
        uint64_t space_addr = reinterpret_cast<uint64_t>(space);
        space_offset_ = space_addr - this_addr;
      } else {
        space_offset_ = 0;
      }
    } else {
      space_offset_ = 0;
    }
  }

  // Assignment from nullptr
  PersistentPtr &operator=(decltype(nullptr)) noexcept {
    data_offset_ = 0;
    return *this;
  }

  // Get the allocator space using self-relative offset
  allocator_space_t *get_space() const noexcept {
    if (space_offset_ == 0) {
      return nullptr;
    }
    uint64_t this_addr = reinterpret_cast<uint64_t>(this);
    return reinterpret_cast<allocator_space_t *>(this_addr + space_offset_);
  }

  // Get raw pointer - NO space parameter needed!
  T *get() const noexcept {
    if (data_offset_ == 0) {
      return nullptr;
    }
    allocator_space_t *space = get_space();
    if (!space) {
      return nullptr;
    }
    uint64_t base = reinterpret_cast<uint64_t>(space);
    return reinterpret_cast<T *>(base + data_offset_);
  }

  // Get the raw data offset (for debugging/serialization)
  persistent_offset_t get_data_offset() const noexcept { return data_offset_; }

  // Get the raw space offset (for debugging)
  int64_t get_space_offset() const noexcept { return space_offset_; }

  // Standard pointer operations - NO space parameter needed!
  T &operator*() const noexcept { return *get(); }

  T *operator->() const noexcept { return get(); }

  T &operator[](difference_type index) const noexcept { return get()[index]; }

  // Pointer arithmetic - returns new PersistentPtr
  PersistentPtr operator+(difference_type n) const noexcept {
    if (data_offset_ == 0) {
      return PersistentPtr();
    }

    // Create new pointer with adjusted data offset
    PersistentPtr result;
    result.data_offset_ = data_offset_ + n * sizeof(T);

    // Calculate space_offset for the result
    allocator_space_t *space = get_space();
    if (space) {
      uint64_t result_addr = reinterpret_cast<uint64_t>(&result);
      uint64_t space_addr = reinterpret_cast<uint64_t>(space);
      result.space_offset_ = space_addr - result_addr;
    }

    return result;
  }

  PersistentPtr operator-(difference_type n) const noexcept {
    return *this + (-n);
  }

  PersistentPtr &operator+=(difference_type n) noexcept {
    data_offset_ += n * sizeof(T);
    return *this;
  }

  PersistentPtr &operator-=(difference_type n) noexcept {
    data_offset_ -= n * sizeof(T);
    return *this;
  }

  PersistentPtr &operator++() noexcept {
    data_offset_ += sizeof(T);
    return *this;
  }

  PersistentPtr operator++(int) noexcept {
    PersistentPtr tmp = *this;
    ++(*this);
    return tmp;
  }

  PersistentPtr &operator--() noexcept {
    data_offset_ -= sizeof(T);
    return *this;
  }

  PersistentPtr operator--(int) noexcept {
    PersistentPtr tmp = *this;
    --(*this);
    return tmp;
  }

  // Pointer difference
  difference_type operator-(const PersistentPtr &other) const noexcept {
    return static_cast<difference_type>(data_offset_ - other.data_offset_) /
           sizeof(T);
  }

  // Comparison operators (compare data offsets)
  bool operator==(const PersistentPtr &other) const noexcept {
    return data_offset_ == other.data_offset_;
  }

  bool operator!=(const PersistentPtr &other) const noexcept {
    return data_offset_ != other.data_offset_;
  }

  bool operator<(const PersistentPtr &other) const noexcept {
    return data_offset_ < other.data_offset_;
  }

  bool operator>(const PersistentPtr &other) const noexcept {
    return data_offset_ > other.data_offset_;
  }

  bool operator<=(const PersistentPtr &other) const noexcept {
    return data_offset_ <= other.data_offset_;
  }

  bool operator>=(const PersistentPtr &other) const noexcept {
    return data_offset_ >= other.data_offset_;
  }

  // Compare with nullptr
  bool operator==(decltype(nullptr)) const noexcept {
    return data_offset_ == 0;
  }

  bool operator!=(decltype(nullptr)) const noexcept {
    return data_offset_ != 0;
  }

  // Boolean conversion
  explicit operator bool() const noexcept { return data_offset_ != 0; }

  // Swap
  void swap(PersistentPtr &other) noexcept {
    persistent_offset_t tmp_data = data_offset_;
    int64_t tmp_space = space_offset_;

    data_offset_ = other.data_offset_;
    space_offset_ = other.space_offset_;

    other.data_offset_ = tmp_data;
    other.space_offset_ = tmp_space;
  }

  // For std::pointer_traits (if available)
  friend T *to_address(const PersistentPtr &p) noexcept { return p.get(); }

  template <typename U> friend class PersistentPtr;

private:
  /*
   * Implementation note: 128bits of pointer seems a bit unexpected, but do we
   * realistically want to pack it?
   */

  // Offset from space->origin to the data
  persistent_offset_t data_offset_;

  // Offset from this pointer's address to the allocator_space_t
  // This is signed because space could be before or after this pointer (if the
  // PersistentPtr is placed outside of its allocator_space)
  int64_t space_offset_;
};

// Helper: Create a PersistentPtr from a raw pointer
template <typename T>
PersistentPtr<T> make_persistent_ptr(T *ptr,
                                     allocator_space_t *space) noexcept {
  return PersistentPtr<T>(ptr, space);
}

// Non-member swap
template <typename T>
void swap(PersistentPtr<T> &a, PersistentPtr<T> &b) noexcept {
  a.swap(b);
}

} // namespace persistent_mem

#endif
