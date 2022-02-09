# DEBUG
Building a small/simplicity focused linux debugger to learn DWARF

![Debug Mockup in Action](/media/debug.gif)

DONE:
- Basic GUI mockup with demo endpoints
- Parse DWARF line and abbrev tables
- Support breakpoints on lines and addresses
- Support hardware watchpoints on variables
- Support basic cmd interface (get list of commands with `h`)

TODO:
- Hook up GUI to debugger backend
- Handle simple user-defined C expressions
- Easy printing memory
- Support for sofware watchpoints
- Load debug info for externally loaded dynamic libraries
- Load and print callstack via .debug_frame
