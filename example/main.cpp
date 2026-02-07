#include "persistent_ptr.hpp"
#include "ring_buffer.hpp"
#include <cstdio>
#include <cstring>

#define VEC_ROOT_CLASS 0x56454300  // "VEC"
#define RING_ROOT_CLASS 0x52494e47 // "RING"

using namespace persistent_mem;

struct VectorRoot {
    PersistentPtr<PersistentPtr<char>> data;
    size_t size;
    size_t capacity;
};

enum Action {
    ACTION_NONE,
    ACTION_ADD,
    ACTION_REMOVE,
    ACTION_GC
};

int main(int argc, char* argv[]) {
    const char* filename = "example_vector.bin";
    const size_t space_size = 10 * 1024 * 1024;

    allocator_space_t* space = create_persistent_allocator(filename, space_size);
    if (!space) {
        fprintf(stderr, "Failed to create persistent allocator\n");
        return 1;
    }

    VectorRoot* root = static_cast<VectorRoot*>(
        persistent_find_root(space, VEC_ROOT_CLASS)
    );

    if (!root) {
        root = static_cast<VectorRoot*>(
            persistent_malloc_root(space, VEC_ROOT_CLASS, sizeof(VectorRoot))
        );
        if (!root) {
            fprintf(stderr, "Failed to allocate root\n");
            destroy_persistent_allocator(space);
            return 1;
        }

        root->data = PersistentPtr<PersistentPtr<char>>(space);
        root->size = 0;
        root->capacity = 0;

        printf("Created new persistent vector\n");
    } else {
        printf("Loaded existing persistent vector\n");
    }

    Action action = ACTION_NONE;
    const char* item = nullptr;

    if (argc > 1) {
        if (strcmp(argv[1], "add") == 0 && argc > 2) {
            action = ACTION_ADD;
            item = argv[2];
        } else if (strcmp(argv[1], "del") == 0 && argc > 2) {
            action = ACTION_REMOVE;
            item = argv[2];
        } else if (strcmp(argv[1], "gc") == 0) {
            action = ACTION_GC;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [add <string>]\n", argv[0]);
            printf("  No args: Print contents of vector\n");
            printf("  add <string>: Add string to vector and print contents\n");
            printf("  del <string>: Remove string (set to null) from vector and print contents\n");
            printf("  gc          : Compact the vector, removing any null elements\n");
            destroy_persistent_allocator(space);
            return 0;
        }
    }

    if (action == ACTION_ADD && item) {
        if (root->size >= root->capacity) {
            size_t new_capacity = root->capacity == 0 ? 4 : root->capacity * 2;
            PersistentPtr<char>* new_data = static_cast<PersistentPtr<char>*>(
                persistent_malloc(space, new_capacity * sizeof(PersistentPtr<char>))
            );

            if (!new_data) {
                fprintf(stderr, "Failed to allocate new data array\n");
                destroy_persistent_allocator(space);
                return 1;
            }

            if (root->data) {
                PersistentPtr<char>* old_data = root->data.get();
                for (size_t i = 0; i < root->size; ++i) {
                    // new_data PersistentPtrs have been initialized yet
                    // so this slightly awkward syntax ensures they are properly initialized
                    new_data[i] = PersistentPtr<char>(old_data[i].get(), space);
                }
                persistent_free(space, old_data);
            }

            root->data = PersistentPtr<PersistentPtr<char>>(new_data, space);
            root->capacity = new_capacity;
        }

        size_t len = strlen(item);
        char* str = static_cast<char*>(persistent_malloc(space, len + 1));
        if (!str) {
            fprintf(stderr, "Failed to allocate string\n");
            destroy_persistent_allocator(space);
            return 1;
        }

        strncpy(str, item, len + 1);

        PersistentPtr<char>* data_array = root->data.get();
        // data_array PersistentPtrs might not have been initialized yet
        // so this slightly awkward syntax ensures they are properly initialized
        data_array[root->size] = PersistentPtr<char>(str, space);
        root->size++;

        printf("Added: \"%s\"\n", item);
    } else if (action == ACTION_REMOVE && item) {
        printf("Removing: \"%s\"\n", item);
        for (auto i = 0; i < root->size; i++) {
            char *stored_string = root->data[i].get();
            if (stored_string && strcmp(item, stored_string) == 0) {
                persistent_free(space, stored_string);
                root->data[i] = nullptr;
            }
        }
    } else if(action == ACTION_GC) {
        printf("Compacting null elements.\n");

        for (auto i = 0; i < root->size; i++) {
            while (!root->data[i]) {
                for (auto j = i; j < root->size - 1; j++) {
                    root->data[j] = root->data[j + 1];
                }
                root->size--;
            }
        }
    }

    printf("\nVector contents (%zu items):\n", root->size);
    if (root->data) {
        PersistentPtr<char>* data_array = root->data.get();
        for (size_t i = 0; i < root->size; ++i) {
            char* str = data_array[i].get();
            printf("  [%zu] \"%s\"\n", i, str ? str : "(null)");
        }
    }

    printf("\nDiagnostics:\n");
    printf("  Space origin: 0x%016lx\n", space->origin);
    printf("  Total size: %lu bytes\n", space->total_size);
    printf("  Heap start: 0x%016lx\n", space->heap_start);
    printf("  Heap end: 0x%016lx\n", space->heap_end.load());
    printf("  Heap extent: %lu bytes\n", space->heap_end.load() - space->heap_start);

    if (root->size > 0 && root->data) {
        PersistentPtr<char>* data_array = root->data.get();
        PersistentPtr<char> first = data_array[0];
        printf("\nFirst item pointer info:\n");
        printf("  Data offset: 0x%016lx\n", first.get_data_offset());
        printf("  Space offset: 0x%016lx\n", first.get_space_offset());
        printf("  Resolved pointer: %p\n", first.get());
        printf("  Space pointer: %p\n", first.get_space());
    }

    destroy_persistent_allocator(space);

    return 0;
}
