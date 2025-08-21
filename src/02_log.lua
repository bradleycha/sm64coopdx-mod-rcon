-- Copyright (c) Chase Bradley 2025
-- src/log.lua: chat box and console logger

local gRconDebug = false
if mod_storage_exists(RCON_SAVE_KEY_DEBUG) then
   gRconDebug = mod_storage_load_bool(RCON_SAVE_KEY_DEBUG)
end

local RCON_LOG_LEVEL_DEBUG    = 0
local RCON_LOG_LEVEL_INFO     = 1
local RCON_LOG_LEVEL_WARNING  = 2
local RCON_LOG_LEVEL_ERROR    = 3

local RCON_LOG_DESTINATION_BIT_CONSOLE  = 1
local RCON_LOG_DESTINATION_BIT_TEXTBOX  = 2

local function rcon_log(level, destination, message)
   local RCON_LOG_COLOR_DEBUG    = "\\#6000a0\\"
   local RCON_LOG_COLOR_INFO     = "\\#90f090\\"
   local RCON_LOG_COLOR_WARNING  = "\\#f0f090\\"
   local RCON_LOG_COLOR_ERROR    = "\\#b02020\\"

   local color = nil
   local djui_level = nil
   if level == RCON_LOG_LEVEL_DEBUG then
      if not gRconDebug then
         return
      end

      color = RCON_LOG_COLOR_DEBUG
      djui_level = CONSOLE_MESSAGE_INFO
   elseif level == RCON_LOG_LEVEL_INFO then
      color = RCON_LOG_COLOR_INFO
      djui_level = CONSOLE_MESSAGE_INFO
   elseif level == RCON_LOG_LEVEL_WARNING then
      color = RCON_LOG_COLOR_WARNING
      djui_level = CONSOLE_MESSAGE_WARNING
   elseif level == RCON_LOG_LEVEL_ERROR then
      color = RCON_LOG_COLOR_ERROR
      djui_level = CONSOLE_MESSAGE_ERROR
   else
      -- done to prevent bad packets from causing problems
      return
   end

   if (destination & RCON_LOG_DESTINATION_BIT_CONSOLE) ~= 0 then
      log_to_console("rcon: " .. message, djui_level)
   end
   if (destination & RCON_LOG_DESTINATION_BIT_TEXTBOX) ~= 0 then
      djui_chat_message_create(color .. message)
   end

   return
end

local function rcon_log_console(level, message)
   rcon_log(level, RCON_LOG_DESTINATION_BIT_CONSOLE, message)
   return
end

local function rcon_log_textbox(level, message)
   rcon_log(level, RCON_LOG_DESTINATION_BIT_TEXTBOX, message)
   return
end

local function rcon_log_all(level, message)
   local destination = RCON_LOG_DESTINATION_BIT_CONSOLE | RCON_LOG_DESTINATION_BIT_TEXTBOX

   rcon_log(level, destination, message)

   return
end

