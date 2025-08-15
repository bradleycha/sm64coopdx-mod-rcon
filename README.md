# Remote Console v1.0.0

A mod for Super Mario 64 Online Coop Deluxe which allows for players to remotely
commands and messages from the host.

## Installation

Installing requires building a patched `sm64coopdx` build for the server as well
as installing the lua file to the mods folder.  Clients connecting to the server
do not need to be patched.

### Building the Server

Obtain sources and set up the build environment for `sm64coopdx` as you normally
would.  Then, type the following command to apply the server patches:

```
cd [PATH_TO_SM64COOPDX_SOURCES]
git apply [PATH_TO_MOD]/rcon.patch
```

This will patch the source code to allow using the remote console.  You can now
build `sm64coopdx` and install it as you usually do.

### Installing the Lua File

Next, install the lua file which will run on both the server and any connected
clients.  This can simply be done by copying `rcon.lua` to your mods folder.

## Usage

When in-game, you can type either `/rcon` or `/rcon help` for basic commands and
usage information.

### Setting the Password

When you first install Remote Console, there will be no password.  This will
make it impossible for clients to login to the remote console, so you will have
to set the password.  This can be done with the following command:

```
/rcon password [password]
```

### Changing the Maximum Login Attempts

If a client tries to log in too many times, the server will block all future
login attempts, even if the password is correct, until the client disconnects
and reconnects.

To change the maximum allowed login attempts, type the following command:

```
/rcon max-attempts [count]
```

### Monitoring Player Activity

Due to the sensitive nature of the remote console, extensive logging is
performed during operation.  You can view log messages in the in-game console,
and some of the more important log messages are sent to the host's chat box.  As
of `sm64coopdx` version `1.3.2`, logging lua console output to `stdout` requires
patches to the server.  This is important for those looking to run a headless
server, as logging malicious player activity for server networks could be
extremely valuable.

