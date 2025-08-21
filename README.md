# Remote Console v1.2.0

A mod for Super Mario 64 Online Coop Deluxe which allows for players to remotely
commands and messages from the host.

## Warning

This mod adds a Lua function which allows scripts to send chat messages as if
you sent them yourself.  If you host servers with this mod, make sure you only
install trusted mods and join trusted servers.  Otherwise, a malicious script
could force you to send malicious chat messages to get you banned from CoopNet.
If you are only joining a server with this mod, there is no safety risk as only
hosts will have the dangerous Lua function.  However, if you host servers with
this mod and then join servers with the same build of `sm64coopdx`, the above
could happen, so be careful.  It's recommended to have a seperate build of
`sm64coopdx` dedicated to hosting with this mod, and then use a vanilla client
when joining servers.

## Installation

Installing requires building a patched `sm64coopdx` build for the server as well
as building and installing the lua files to the mods folder.  Clients connecting 
to the server do not need to be patched with `rcon.patch`.

### Building the Release

To build a release from source, type the following command while in the source
code directory:

```
make
```

This will build all the release files under `build/rcon-1.2.0`.  The rest of the
files will be relative to this directory.

### Building the Server

Obtain sources and set up the build environment for `sm64coopdx` as you normally
would.  Then, type the following command to apply the server patches:

```
cd [PATH_TO_SM64COOPDX_SOURCES]
git apply [PATH_TO_RELEASE]/rcon.patch
```

This will patch the source code to allow using the remote console.  You can now
build `sm64coopdx` and install it as you usually do.

### Installing the Mod

Next, install the lua file which will run on both the server and any connected
clients.  This can simply be done by copying `[PATH_TO_RELEASE]/rcon` to your mods folder.

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

### Changing the login timeout duration

If a player tries to login too quickly after a failed login attempt, the login
attempt will be rejected, even if the password is correct.  This duration is
measured in seconds.

To change the login timeout duration, type the following command:

```
/rcon timeout-duration [seconds]
```

### Changing the UUID lifespan

Each player is assigned a private 64-bit UUID.  If an attacker gains another
player's UUID, that attacker can impersonate the player.  Thus, we want to make
sure this never happens.  To help prevent this, UUIDs are only valid for a
period of time.  Once a UUID expires, a new one is generated and sent to the
corresponding player.

To change how often UUIDs are regenerated, use the following command:

```
/rcon uuid-lifespan [seconds]
```

### Monitoring Player Activity

Due to the sensitive nature of the remote console, extensive logging is
performed during operation.  You can view log messages in the in-game console,
and some of the more important log messages are sent to the host's chat box.  As
of `sm64coopdx` version `1.3.2`, logging lua console output to `stdout` requires
patches to the server.  This is important for those looking to run a headless
server, as logging malicious player activity for server networks could be
extremely valuable.

