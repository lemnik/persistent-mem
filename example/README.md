A simple example app demonstrating the use of `persistent_mem`. The app creates and edits a simple list of strings in a persistent block of memory. Each run maps the file (initializing if it doesn't exist) performs an action (`add`/`del`/`gc`) and then lists the content of the list and some space stats. 

- ./example add <some string> - appends a new item to the end of the list
- ./example del <some string> - deletes all occurrences of a given string from the list (nulling them)
- ./example gc - compacts the list, removing any null-pointers (not a real GC, just a list compact)

Example use:
```
$ ./example add "message one"
Created new persistent vector
Added: "message one"

Vector contents (1 items):
  [0] "message one"

Diagnostics:
  Space origin: 0x00007be6f7c00000
  Total size: 10485760 bytes
  Heap start: 0x00000000000000d8
  Heap end: 0x00000000000001a8
  Heap extent: 208 bytes

First item pointer info:
  Data offset: 0x0000000000000188
  Space offset: 0xfffffbe77e9b5500
  Resolved pointer: 0x7be6f7c00188
  Space pointer: 0x7be6f7c00000
```