-- Copyright (c) Chase Bradley
-- src/utils.lua: generic helper functions

local function rcon_utils_base16_encode(data)
   local str = ""

   for i = 1, #data do
      local byte = string.byte(data:sub(i,i))
      local hexits = string.format("%02x", byte)
      str = str .. hexits
   end

   return str
end

local function rcon_utils_base16_decode(str)
   local data = ""

   for i = 1, #str/2 do
      local hexits = str:sub(i*2 - 1, i*2)
      
      local byte = tonumber("0x" .. hexits)
      if byte == nil then
         rcon_log_console(RCON_LOG_LEVEL_ERROR, "failed to decode base-16 string \'" .. str .. "\'")
         return
      end

      data = data .. string.char(byte)
   end

   return data
end

