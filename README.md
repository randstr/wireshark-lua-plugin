
## Introduction

This is a plugin for [Wireshark](https://www.wireshark.org/) providing Lua 5.4 bindings to the libwireshark
API. It allows writing Wireshark dissectors in Lua instead of C.

It was written from scratch as an experimental alternative to the code using
Lua 5.2 that comes with Wireshark 3.6 and later versions.

This is an external project to Wireshark and not officially supported by the
Wireshark developer team.

The [API documentation](https://jvalverde.gitlab.io/wireshark-lua-plugin) is
still a work in progress.

## Goals and non-goals

Goals for the project include:

* Better Lua API
* Better C code
* Better unit testing framework
* Better user documentation
* Fix some design flaws and limitations with Lua support in Wireshark 3.6+
* Modernize the version of Lua used with Wireshark 3.6+

Non-goals are backward compatibility and one-to-one feature parity.

## Installing from source

### Binary and source compatibility

To use the plugin you will have to install Wireshark or build it from source
code. This plugin is under development and should be compiled and tested against
the tip of the development branch for Wireshark. In the future other plugin
branches will be created to support Wireshark stable releases.

### Building Wireshark

Briefly from the Wireshark source directory run:

```sh
WIRESHARK_PREFIX=/opt/wireshark
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=$WIRESHARK_PREFIX /path/to/wireshark/source
ninja
sudo ninja install
sudo ninja install-headers
```

Check the [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)
for detailed instructions on how to build Wireshark itself. Note that header
installation is a separate install step and it is required to build any Wireshark plugin.

### Building the Wireshark Lua Plugin

From the plugin source directory run:

```sh
mkdir build && cd build
cmake -DCMAKE_PREFIX_PATH=$WIRESHARK_PREFIX /path/to/plugin/source
make
make docs
```

Use of `CMAKE_PREFIX_PATH` is required if Wireshark was installed outside
the default CMake `find_package()` search paths for your platform. Usually
this is only the case if you are also compiling Wireshark itself.

To run the tests:

```sh
make test
```

To install the plugin on the system (may need to use sudo):

```sh
make install
```

## Installing from a binary release

Compiled plugin binary snapshots are provided for Windows and Linux. Since
Wireshark 4.3 the easiest way to install the plugin is to run the Wireshark GUI
and select the "Install Plugin" option from the Tools menu, then select the
downloaded plugin binary file in the file dialog. Wireshark will then install
it to the personal plugins folder after running some compatibility checks.

Please note that these plugin binary snapshots can be out-of-date and are
intended to allow people in a hurry to test the code. Compiling from source
is recommended for best compatibility with the Wireshark development branch.

## Loading Lua scripts

Dissectors written in Lua using this plugin should be copied into a folder
named "wslua2". The folder needs to be created inside Wireshark's configuration
directory `$XDG_CONFIG_HOME/wireshark`.

Any file with the extension ".lua" is automatically loaded.
You may also use "init.lua" for custom initialization code.
