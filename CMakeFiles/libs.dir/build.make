# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/cryptoeng/SLWL11

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/cryptoeng/SLWL11

# Include any dependencies generated for this target.
include CMakeFiles/libs.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/libs.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/libs.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/libs.dir/flags.make

CMakeFiles/libs.dir/lib/lib-mesg.c.o: CMakeFiles/libs.dir/flags.make
CMakeFiles/libs.dir/lib/lib-mesg.c.o: lib/lib-mesg.c
CMakeFiles/libs.dir/lib/lib-mesg.c.o: CMakeFiles/libs.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/cryptoeng/SLWL11/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/libs.dir/lib/lib-mesg.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/libs.dir/lib/lib-mesg.c.o -MF CMakeFiles/libs.dir/lib/lib-mesg.c.o.d -o CMakeFiles/libs.dir/lib/lib-mesg.c.o -c /home/ubuntu/cryptoeng/SLWL11/lib/lib-mesg.c

CMakeFiles/libs.dir/lib/lib-mesg.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libs.dir/lib/lib-mesg.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ubuntu/cryptoeng/SLWL11/lib/lib-mesg.c > CMakeFiles/libs.dir/lib/lib-mesg.c.i

CMakeFiles/libs.dir/lib/lib-mesg.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libs.dir/lib/lib-mesg.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ubuntu/cryptoeng/SLWL11/lib/lib-mesg.c -o CMakeFiles/libs.dir/lib/lib-mesg.c.s

CMakeFiles/libs.dir/lib/lib-misc.c.o: CMakeFiles/libs.dir/flags.make
CMakeFiles/libs.dir/lib/lib-misc.c.o: lib/lib-misc.c
CMakeFiles/libs.dir/lib/lib-misc.c.o: CMakeFiles/libs.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/cryptoeng/SLWL11/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/libs.dir/lib/lib-misc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/libs.dir/lib/lib-misc.c.o -MF CMakeFiles/libs.dir/lib/lib-misc.c.o.d -o CMakeFiles/libs.dir/lib/lib-misc.c.o -c /home/ubuntu/cryptoeng/SLWL11/lib/lib-misc.c

CMakeFiles/libs.dir/lib/lib-misc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libs.dir/lib/lib-misc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ubuntu/cryptoeng/SLWL11/lib/lib-misc.c > CMakeFiles/libs.dir/lib/lib-misc.c.i

CMakeFiles/libs.dir/lib/lib-misc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libs.dir/lib/lib-misc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ubuntu/cryptoeng/SLWL11/lib/lib-misc.c -o CMakeFiles/libs.dir/lib/lib-misc.c.s

CMakeFiles/libs.dir/lib/lib-timing.c.o: CMakeFiles/libs.dir/flags.make
CMakeFiles/libs.dir/lib/lib-timing.c.o: lib/lib-timing.c
CMakeFiles/libs.dir/lib/lib-timing.c.o: CMakeFiles/libs.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/cryptoeng/SLWL11/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/libs.dir/lib/lib-timing.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/libs.dir/lib/lib-timing.c.o -MF CMakeFiles/libs.dir/lib/lib-timing.c.o.d -o CMakeFiles/libs.dir/lib/lib-timing.c.o -c /home/ubuntu/cryptoeng/SLWL11/lib/lib-timing.c

CMakeFiles/libs.dir/lib/lib-timing.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libs.dir/lib/lib-timing.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ubuntu/cryptoeng/SLWL11/lib/lib-timing.c > CMakeFiles/libs.dir/lib/lib-timing.c.i

CMakeFiles/libs.dir/lib/lib-timing.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libs.dir/lib/lib-timing.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ubuntu/cryptoeng/SLWL11/lib/lib-timing.c -o CMakeFiles/libs.dir/lib/lib-timing.c.s

CMakeFiles/libs.dir/src/elgamal-mod.c.o: CMakeFiles/libs.dir/flags.make
CMakeFiles/libs.dir/src/elgamal-mod.c.o: src/elgamal-mod.c
CMakeFiles/libs.dir/src/elgamal-mod.c.o: CMakeFiles/libs.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/cryptoeng/SLWL11/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/libs.dir/src/elgamal-mod.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/libs.dir/src/elgamal-mod.c.o -MF CMakeFiles/libs.dir/src/elgamal-mod.c.o.d -o CMakeFiles/libs.dir/src/elgamal-mod.c.o -c /home/ubuntu/cryptoeng/SLWL11/src/elgamal-mod.c

CMakeFiles/libs.dir/src/elgamal-mod.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libs.dir/src/elgamal-mod.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ubuntu/cryptoeng/SLWL11/src/elgamal-mod.c > CMakeFiles/libs.dir/src/elgamal-mod.c.i

CMakeFiles/libs.dir/src/elgamal-mod.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libs.dir/src/elgamal-mod.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ubuntu/cryptoeng/SLWL11/src/elgamal-mod.c -o CMakeFiles/libs.dir/src/elgamal-mod.c.s

# Object files for target libs
libs_OBJECTS = \
"CMakeFiles/libs.dir/lib/lib-mesg.c.o" \
"CMakeFiles/libs.dir/lib/lib-misc.c.o" \
"CMakeFiles/libs.dir/lib/lib-timing.c.o" \
"CMakeFiles/libs.dir/src/elgamal-mod.c.o"

# External object files for target libs
libs_EXTERNAL_OBJECTS =

build/liblibs.a: CMakeFiles/libs.dir/lib/lib-mesg.c.o
build/liblibs.a: CMakeFiles/libs.dir/lib/lib-misc.c.o
build/liblibs.a: CMakeFiles/libs.dir/lib/lib-timing.c.o
build/liblibs.a: CMakeFiles/libs.dir/src/elgamal-mod.c.o
build/liblibs.a: CMakeFiles/libs.dir/build.make
build/liblibs.a: CMakeFiles/libs.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ubuntu/cryptoeng/SLWL11/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C static library build/liblibs.a"
	$(CMAKE_COMMAND) -P CMakeFiles/libs.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libs.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/libs.dir/build: build/liblibs.a
.PHONY : CMakeFiles/libs.dir/build

CMakeFiles/libs.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/libs.dir/cmake_clean.cmake
.PHONY : CMakeFiles/libs.dir/clean

CMakeFiles/libs.dir/depend:
	cd /home/ubuntu/cryptoeng/SLWL11 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/cryptoeng/SLWL11 /home/ubuntu/cryptoeng/SLWL11 /home/ubuntu/cryptoeng/SLWL11 /home/ubuntu/cryptoeng/SLWL11 /home/ubuntu/cryptoeng/SLWL11/CMakeFiles/libs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/libs.dir/depend

