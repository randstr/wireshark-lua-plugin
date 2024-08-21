
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

## Building from source

### Binary and source compatibility

The plugin master branch is under development and should be considered
unstable. If using the master branch it is strongly recommended to compile
the plugin from source against Wireshark's master branch. Source and binary
compatibility is not guaranteed and can often break.

Plugin branches tracking a Wireshark stable branch can be expected to have
better compatibility. In particular it should work reasonably well with
official Wireshark releases.

For those in a hurry a plugin binary release is provided for the latest
Wireshark stable branch but keep in mind that although rarer breaks in binary
compatibility can still happen occasionally.

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

### Building the plugin

From the plugin source directory run:

```sh
WIRESHARK_PREFIX=/opt/wireshark
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

## Manual installation of binary plugin

If you are not building from source you need to copy the plugin file
(with extension `.dll` on Windows or `.so` on Linux) to the Wireshark
[personal plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
The following table lists the personal plugin folder per platform:

| Platform    | Plugin folder |
| ----------- | ---- |
| Windows     | `%APPDATA%\Wireshark\plugins\X.Y\epan`           |
| Unix-like   | `$HOME/.local/lib/wireshark/plugins/X.Y/epan`    |

Where X.Y is the major.minor Wireshark version for the release you are
installing for (so the the last component Z in the complete X.Y.Z version number
is not used).

## Loading Lua scripts

Dissectors written in Lua using this plugin should be copied into a folder
named "wslua2". The folder needs to be created inside Wireshark's configuration
directory `$XDG_CONFIG_HOME/wireshark`.

Any file with the extension ".lua" is automatically loaded.
You may also use "init.lua" for custom initialization code.
