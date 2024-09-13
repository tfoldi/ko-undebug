# Linux Kernel Module for Hiding TracerPid and maps (x86_64 and arm64)

Linux kernel module demonstrating usage of **ftrace** framework for 
hiding debugging. The module hooks into the kernel function calls and sets
`TracerPid` value to `0` and removes unwanted entries from
`maps` in /proc/PID directory.

The code is licensed under GPLv2_.

.. _GPLv2: LICENSE

## How to build

 Please consider using **a virtual machine** (VirtulBox, VMWare, QEMU, etc.)
 for experiments. The (unchanged) module is totally harmless and should not
 affect your system stability. But just in case: you are loading it at your
 own risk. Don't kill your own machine or production environment by accident.

Make sure you have installed GCC and Linux kernel headers for your kernel.

### For Debian-based systems

    $ sudo apt install build-essential linux-headers-$(uname -r)

### Build the kernel module

    $ cd ko-undebug
    $ make
    make -C /lib/modules/5.10.176/build M=/home/tfoldi/ko-undebug modules
    make[1]: Entering directory '/usr/src/linux-5.10.176'
    CC [M]  /home/tfoldi/ko-undebug/undebug.o
    MODPOST /home/tfoldi/ko-undebug/Module.symvers
    CC [M]  /home/tfoldi/ko-undebug/undebug.mod.o
    LD [M]  /home/tfoldi/ko-undebug/undebug.ko
    make[1]: Leaving directory '/usr/src/linux-5.10.176'

This should build the module for the kernel you are currently running.
You can load it into your system, experiment, and unload the module
like this:

    $ sudo insmod undebug.ko

Hiding TracerPid from `/proc/self/status`:

    $ strace cat /proc/self/status 2>&1 | grep Trace
    TracerPid:	17968
    $ sudo insmod undebug.ko
    $ strace cat /proc/self/status 2>&1 | grep Trace
    TracerPid:	0


Hiding files from `/proc/self/maps`:

    $ cat /proc/self/maps | head
    aaaacbb10000-aaaacbb18000 r-xp 00000000 fd:00 623                        /usr/bin/cat
    aaaacbb27000-aaaacbb28000 r--p 00007000 fd:00 623                        /usr/bin/cat
    aaaacbb28000-aaaacbb29000 rw-p 00008000 fd:00 623                        /usr/bin/cat
    aaaaf125f000-aaaaf1280000 rw-p 00000000 00:00 0                          [heap]
    ffff84efc000-ffff84f1e000 rw-p 00000000 00:00 0
    ffff84f1e000-ffff84f50000 r--p 00000000 fd:00 2689                       /usr/lib/locale/C.UTF-8/LC_CTYPE
    ffff84f50000-ffff84f51000 r--p 00000000 fd:00 2701                       /usr/lib/locale/C.UTF-8/LC_NUMERIC
    ffff84f51000-ffff84f52000 r--p 00000000 fd:00 2707                       /usr/lib/locale/C.UTF-8/LC_TIME

    $ sudo sysctl -w undebug.hide_maps=cat,LC_CTYPE,LC_NUMERIC
    undebug.hide_maps = cat,LC_CTYPE,LC_NUMERIC
    
    $ cat /proc/self/maps | head
    aaaae640d000-aaaae642e000 rw-p 00000000 00:00 0                          [heap]
    ffff8fabe000-ffff8fae0000 rw-p 00000000 00:00 0
    ffff8fb13000-ffff8fb14000 r--p 00000000 fd:00 2707                       /usr/lib/locale/C.UTF-8/LC_TIME
    ffff8fb14000-ffff8fc87000 r--p 00000000 fd:00 2687                       /usr/lib/locale/C.UTF-8/LC_COLLATE
    ffff8fc87000-ffff8fc88000 r--p 00000000 fd:00 2697                       /usr/lib/locale/C.UTF-8/LC_MONETARY
    ffff8fc88000-ffff8fc89000 r--p 00000000 fd:00 2695                       /usr/lib/locale/C.UTF-8/LC_MESSAGES/SYS_LC_MESSAGES
    ffff8fc89000-ffff8fc8a000 r--p 00000000 fd:00 2703                       /usr/lib/locale/C.UTF-8/LC_PAPER
    ffff8fc8a000-ffff8fc8b000 r--p 00000000 fd:00 2699                       /usr/lib/locale/C.UTF-8/LC_NAME

### Credits

 * ilammy/Alexey Lozovsky for his awesome ftrace hook lib (https://github.com/ilammy/ftrace-hook)
 * LWSS for https://github.com/LWSS/TracerHid 

