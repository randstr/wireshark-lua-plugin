
## Introduction

This is a plugin for Wireshark providing Lua 5.4 bindings to the libwireshark
API. It allows writing Wireshark dissectors in Lua instead of C.

This is a new experimental alternative to the code using Lua 5.2 that comes
with Wireshark 3.6. It is an external project to Wireshark and not officially
supported by the Wireshark developer team.

## Goals and non-goals

Goals for the project include:
 * Better Lua API
 * Better C code
 * Better unit testing framework
 * Better user documentation
 * Fix some design flaws and limitations with Lua support in Wireshark 3.6
 * Modernize the version of Lua used with Wireshark 3.6

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
    $ make docs

To install the plugin to use with Wireshark you may need to use sudo or run
as root. To run the tests you need to install the plugin first because the
test suite uses the tshark binary:

    $ make install
    $ make test

## Loading Lua scripts

Dissectors written in Lua using this plugin should be copied into a folder
named "wslua2". The folder needs to be created inside Wireshark's Lua personal
script folder (also called Lua plugins in Wireshark). The personal Lua plugin
folder paths can be consulted in Wireshark or TShark:

    $ tshark -G folders

Any file with the extension ".lua" is automatically loaded.
You may also use "init.lua" for custom initialization code.
