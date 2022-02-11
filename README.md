# DEBUG
Building a small/simplicity focused linux debugger to learn DWARF

![Debug in Action](/media/debug.gif)

DONE:
- GUI with basic interaction support
- Parse DWARF line and abbrev tables
- Support breakpoints on lines and addresses
- Support hardware watchpoints on variables

TODO:
- Handle simple user-defined C expressions
- Easy printing memory
- Support for sofware watchpoints
- Load debug info for externally loaded dynamic libraries
- Load and print callstack via .debug_frame
- Overhaul internal line<>address table representation
