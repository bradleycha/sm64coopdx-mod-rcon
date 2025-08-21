# Copyright (c) Chase Bradley 2025
# Makefile: GNU Makefile script to compile Lua scripts to bytecode

VERSION := 1.2.0
RELEASE := rcon-$(VERSION)

LUAC ?= luac
MKDIR ?= mkdir
CD ?= cd
CP ?= cp
RM ?= rm
CAT ?= cat
TAR ?= tar
ZIP ?= zip

LUAC_FLAGS ?= -s

ROOT_DIR ?= .
SRC_DIR ?= $(ROOT_DIR)/src
BUILD_DIR ?= $(ROOT_DIR)/build
BUILD_RELEASE_DIR ?= $(BUILD_DIR)/$(RELEASE)

LUA_SOURCES = \
	$(SRC_DIR)/00_utils.lua \
	$(SRC_DIR)/01_save.lua \
	$(SRC_DIR)/02_log.lua \
	$(SRC_DIR)/03_password.lua \
	$(SRC_DIR)/04_rcon.lua \
	$(SRC_DIR)/05_cmd.lua

.DEFAULT_GOAL := all
all : $(BUILD_RELEASE_DIR)/rcon/rcon.luac $(BUILD_RELEASE_DIR)/rcon/main.lua $(BUILD_RELEASE_DIR)/rcon.patch $(BUILD_RELEASE_DIR)/LICENSE
dist : dist-tar-xz dist-zip
dist-tar-xz : $(BUILD_DIR)/$(RELEASE).tar.xz
dist-zip : $(BUILD_DIR)/$(RELEASE).zip

clean : 
	$(RM) -rf $(BUILD_DIR)

$(BUILD_DIR)/$(RELEASE).tar.xz : all
	( $(CD) $(BUILD_DIR); $(TAR) cJvf $(RELEASE).tar.xz $(RELEASE) )

$(BUILD_DIR)/$(RELEASE).zip : all
	( $(CD) $(BUILD_DIR); $(ZIP) -r $(RELEASE).zip $(RELEASE) )

$(BUILD_RELEASE_DIR)/rcon/rcon.luac : $(LUA_SOURCES) $(BUILD_RELEASE_DIR) $(BUILD_RELEASE_DIR)/rcon
	$(CAT) $(LUA_SOURCES) | $(LUAC) $(LUAC_FLAGS) -o $@ -

$(BUILD_RELEASE_DIR)/rcon/main.lua : $(SRC_DIR)/main.lua
	$(CP) $< $@

$(BUILD_RELEASE_DIR)/rcon.patch : $(SRC_DIR)/rcon.patch
	$(CP) $< $@

$(BUILD_RELEASE_DIR)/LICENSE : $(ROOT_DIR)/LICENSE
	$(CP) $< $@

$(BUILD_DIR) $(BUILD_RELEASE_DIR) $(BUILD_RELEASE_DIR)/rcon :
	$(MKDIR) -p $@

