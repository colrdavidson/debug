# DEBUG
Building a small/simplicity focused linux debugger to learn DWARF

DONE:
- Parse DWARF line and abbrev tables
- Support breakpoints on lines and addresses
- Support hardware watchpoints on variables
- Support basic cmd interface (get list of commands with `h`)

TODO:
- Render a nice looking GUI
- Handle simple user-defined C expressions
- Easy printing memory
- Support for sofware watchpoints
- Load debug info for externally loaded dynamic libraries
- Load and print callstack via .debug_frame
