
## Introduction

This is a plugin for Wireshark providing Lua 5.4 bindings to the libwireshark
API. It allows writing Wireshark dissectors in Lua instead of C.

This is a new experimental alternative to the code using Lua 5.2 that comes
with Wireshark. It is an external project to Wireshark and not officially
supported by the Wireshark developer team.

## Goals and non-goals

Goals include:
 * Better Lua API
 * Better C code
 * Better user documentation
 * Fix some design flaws and limitations with Lua support in Wireshark 3.6

Non-goals are backward compatibility and one-to-one feature parity.

## Building from source

To use the plugin you'll have to build Wireshark from the master branch.

    $ PREFIX=/opt/wireshark
    $ cmake -DCMAKE_INSTALL_PREFIX=$PREFIX /path/to/source
    $ make
    $ sudo make install

To build the plugin:

    $ cmake -DCMAKE_PREFIX_PATH=$PREFIX /path/to/source
    $ make
    $ make test
    $ make docs

To install you may need to use sudo or run as root:

    $ make install
