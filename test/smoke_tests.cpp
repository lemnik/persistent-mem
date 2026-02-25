#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "doctest.h"
#include "persistent_mem.h"

#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>

// Util to create temp file for testing
static std::string create_temp_file() {
    char tmpl[] = "/tmp/pmem_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd != -1) {
        close(fd);
        unlink(tmpl);
    }
    return std::string(tmpl);
}

TEST_CASE("Basic allocation and deallocation") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 1024 * 1024);
    REQUIRE(space != nullptr);

    SUBCASE("Simple allocation") {
        void* ptr = persistent_malloc(space, 64);
        REQUIRE(ptr != nullptr);

        // Write and read back
        memset(ptr, 0xAB, 64);
        CHECK(((unsigned char*)ptr)[0] == 0xAB);
        CHECK(((unsigned char*)ptr)[63] == 0xAB);

        persistent_free(space, ptr);
    }

    SUBCASE("Multiple allocations") {
        void* ptr1 = persistent_malloc(space, 128);
        void* ptr2 = persistent_malloc(space, 256);
        void* ptr3 = persistent_malloc(space, 512);

        REQUIRE(ptr1 != nullptr);
        REQUIRE(ptr2 != nullptr);
        REQUIRE(ptr3 != nullptr);

        // Ensure they don't overlap
        CHECK(ptr1 != ptr2);
        CHECK(ptr2 != ptr3);
        CHECK(ptr1 != ptr3);

        persistent_free(space, ptr1);
        persistent_free(space, ptr2);
        persistent_free(space, ptr3);
    }

    SUBCASE("Zero-size allocation") {
        void* ptr = persistent_malloc(space, 0);
        // Implementation-defined: may return NULL or valid pointer
        if (ptr != nullptr) {
            persistent_free(space, ptr);
        }
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Allocation failure conditions") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 8192);
    REQUIRE(space != nullptr);

    SUBCASE("Exhaust memory") {
        std::vector<void*> ptrs;
        void* ptr;

        // Allocate until we fail
        while ((ptr = persistent_malloc(space, 512)) != nullptr) {
            ptrs.push_back(ptr);
            if (ptrs.size() > 100) break; // Safety limit
        }

        // Should eventually fail
        CHECK(persistent_malloc(space, 512) == nullptr);

        // Clean up
        for (auto p : ptrs) {
            persistent_free(space, p);
        }
    }

    SUBCASE("Allocation larger than available space") {
        void* ptr = persistent_malloc(space, 10 * 1024 * 1024);
        CHECK(ptr == nullptr);
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Free edge cases") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 1024 * 1024);
    REQUIRE(space != nullptr);

    SUBCASE("Free NULL pointer") {
        // Should not crash
        persistent_free(space, nullptr);
        CHECK(true); // If we get here, it didn't crash
    }

    SUBCASE("Double free") {
        void* ptr = persistent_malloc(space, 64);
        REQUIRE(ptr != nullptr);

        persistent_free(space, ptr);
        // Second free - behavior is undefined but shouldn't crash
        // Not testing this as it's undefined behavior
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Reallocation") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 1024 * 1024);
    REQUIRE(space != nullptr);

    SUBCASE("Grow allocation") {
        void* ptr = persistent_malloc(space, 64);
        REQUIRE(ptr != nullptr);

        memset(ptr, 0xCD, 64);

        REQUIRE(persistent_realloc(space, ptr, 128));

        // First 64 bytes should be preserved
        CHECK(((unsigned char*)ptr)[0] == 0xCD);
        CHECK(((unsigned char*)ptr)[63] == 0xCD);

        persistent_free(space, ptr);
    }

    SUBCASE("Shrink allocation") {
        void* ptr = persistent_malloc(space, 256);
        REQUIRE(ptr != nullptr);

        memset(ptr, 0xEF, 256);

        REQUIRE(persistent_realloc(space, ptr, 64));

        // Data should be preserved
        CHECK(((unsigned char*)ptr)[0] == 0xEF);
        CHECK(((unsigned char*)ptr)[63] == 0xEF);

        persistent_free(space, ptr);
    }

    SUBCASE("Realloc NULL pointer") {
        char *ptr = nullptr;
        REQUIRE_FALSE(persistent_realloc(space, ptr, 128));
        persistent_free(space, ptr);
    }

    SUBCASE("Realloc to zero size") {
        void* ptr = persistent_malloc(space, 64);
        REQUIRE(ptr != nullptr);

        // Should return false
        REQUIRE_FALSE(persistent_realloc(space, ptr, 0));
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Root allocations") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 1024 * 1024);
    REQUIRE(space != nullptr);

    SUBCASE("Create and find root") {
        const uint64_t ROOT_CLASS = 0x1234567890ABCDEF;

        void* root = persistent_malloc_root(space, ROOT_CLASS, 128);
        REQUIRE(root != nullptr);

        memset(root, 0x42, 128);

        void* found = persistent_find_root(space, ROOT_CLASS);
        REQUIRE(found != nullptr);
        CHECK(found == root);
        CHECK(((unsigned char*)found)[0] == 0x42);
    }

    SUBCASE("Multiple roots") {
        void* root1 = persistent_malloc_root(space, 1, 64);
        void* root2 = persistent_malloc_root(space, 2, 128);
        void* root3 = persistent_malloc_root(space, 3, 256);

        REQUIRE(root1 != nullptr);
        REQUIRE(root2 != nullptr);
        REQUIRE(root3 != nullptr);

        CHECK(persistent_find_root(space, 1) == root1);
        CHECK(persistent_find_root(space, 2) == root2);
        CHECK(persistent_find_root(space, 3) == root3);
    }

    SUBCASE("Find non-existent root") {
        void* found = persistent_find_root(space, 0xDEADBEEF);
        CHECK(found == nullptr);
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("persistent_ptr validation") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 1024 * 1024);
    REQUIRE(space != nullptr);

    SUBCASE("Valid persistent pointer") {
        void* ptr = persistent_malloc(space, 64);
        REQUIRE(ptr != nullptr);

        void* validated = persistent_ptr(space, ptr);
        CHECK(validated == ptr);

        persistent_free(space, ptr);
    }

    SUBCASE("NULL pointer") {
        void* validated = persistent_ptr(space, nullptr);
        CHECK(validated == nullptr);
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Thread safety - concurrent allocations") {
    const int NUM_THREADS = 8;
    const int ALLOCS_PER_THREAD = 100;

    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 4096 + (NUM_THREADS * ALLOCS_PER_THREAD * 128));
    REQUIRE(space != nullptr);

    std::vector<std::thread> threads;
    std::vector<std::vector<void*>> thread_ptrs(NUM_THREADS);

    for (int t = 0; t < NUM_THREADS; t++) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < ALLOCS_PER_THREAD; i++) {
                size_t size = 64;
                void* ptr = persistent_malloc(space, size);
                if (ptr != nullptr) {
                    memset(ptr, t, size);
                    thread_ptrs[t].push_back(ptr);
                }
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Verify allocations
    int total_allocs = 0;
    for (int t = 0; t < NUM_THREADS; t++) {
        for (void* ptr : thread_ptrs[t]) {
            CHECK(ptr != nullptr);
            CHECK(((unsigned char*)ptr)[0] == t);
            total_allocs++;
        }
    }

    CHECK(total_allocs > 0);

    // Free in parallel
    threads.clear();
    for (int t = 0; t < NUM_THREADS; t++) {
        threads.emplace_back([&, t]() {
            for (void* ptr : thread_ptrs[t]) {
                persistent_free(space, ptr);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}


TEST_CASE("Thread safety - mixed operations") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 10 * 1024 * 1024);
    REQUIRE(space != nullptr);

    const int NUM_THREADS = 4;
    const int ITERATIONS = 200;

    std::vector<std::thread> threads;

    for (int t = 0; t < NUM_THREADS; t++) {
        threads.emplace_back([&]() {
            // Each thread has its own local vector - no sharing
            std::vector<void*> my_ptrs;

            for (int i = 0; i < ITERATIONS; i++) {
                if (i % 3 == 0 && !my_ptrs.empty()) {
                    // Free some from our own list
                    size_t idx = i % my_ptrs.size();
                    persistent_free(space, my_ptrs[idx]);
                    my_ptrs.erase(my_ptrs.begin() + idx);
                } else {
                    // Allocate
                    size_t size = 32 + (i % 20) * 32;
                    void* ptr = persistent_malloc(space, size);
                    if (ptr != nullptr) {
                        memset(ptr, 0xFF, size);
                        my_ptrs.push_back(ptr);
                    }
                }
            }

            // Clean up remaining
            for (void* ptr : my_ptrs) {
                persistent_free(space, ptr);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}

TEST_CASE("Stress test - fragmentation handling") {
    auto filename = create_temp_file();
    auto* space = create_persistent_allocator(filename.c_str(), 2 * 1024 * 1024);
    REQUIRE(space != nullptr);

    std::vector<void*> ptrs;

    // Allocate many small blocks
    for (int i = 0; i < 1000; i++) {
        void* ptr = persistent_malloc(space, 64 + (i % 10) * 16);
        if (ptr != nullptr) {
            ptrs.push_back(ptr);
        }
    }

    // Free every other block to create fragmentation
    for (size_t i = 0; i < ptrs.size(); i += 2) {
        persistent_free(space, ptrs[i]);
        ptrs[i] = nullptr;
    }

    // Try to allocate in fragmented space
    void* new_ptr = persistent_malloc(space, 128);
    CHECK(new_ptr != nullptr);

    if (new_ptr) {
        persistent_free(space, new_ptr);
    }

    // Clean up
    for (void* ptr : ptrs) {
        if (ptr != nullptr) {
            persistent_free(space, ptr);
        }
    }

    destroy_persistent_allocator(space);
    unlink(filename.c_str());
}
