-- Copyright (c) Chase Bradley 2025
-- src/cmd.lua: chat command parser

local function rcon_cmd_parse_help()
   -- It seems that the game limits the number of newlines per chat message, so
   -- we need to split this across multiple chat messages.
   djui_chat_message_create(
      "\\#f0a0a0\\Remote console command list:\n" ..
      "\\#a0a0a0\\   help\\#ffffff\\ - Display the help menu\n" ..
      "\\#a0a0a0\\   login \\#9090f0\\[password]\\#ffffff\\ - Authenticate with the server to get remote console privilege\n" ..
      "\\#a0a0a0\\   send \\#9090f0\\[message]\\#ffffff\\ - Remotely send a chat message as the host\n" ..
      "\\#a0a0a0\\   password \\#9090f0\\[password]\\#ffffff\\ - Set the remote console password\n" ..
      "\\#a0a0a0\\   list\\#ffffff\\ - List all players currently authorized with the remote console"
   )
   djui_chat_message_create(
      "\\#a0a0a0\\   deauthall\\#ffffff\\ - Deauthorize all players from the remote console\n" ..
      "\\#a0a0a0\\   max-attempts \\#9090f0\\[count]\\#ffffff\\ - Set the maximum allowed number of login attempts\n" ..
      "\\#a0a0a0\\   timeout-duration \\#9090f0\\[seconds]\\#ffffff\\ - Set the minimum required wait time between login attempts, measured in seconds\n" ..
      "\\#a0a0a0\\   uuid-lifespan \\#9090f0\\[seconds]\\#ffffff\\ - Set the period of time for a player's UUID to be valid, measured in seconds"
   )

   return
end

local function rcon_cmd_parse_login(password)
   if password == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Missing remote console password")
      return
   end

   if network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "You are the host, refusing to login")
      return
   end

   rcon_send_packet_login(password)
   return
end

local function rcon_cmd_parse_send(cmd)
   if cmd == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Missing remote chat message")
      return
   end

   if network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "You are the host, refusing to send message")
      return
   end

   rcon_send_packet_send(cmd)
   return
end

local function rcon_cmd_parse_password(password)
   if password == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Missing new remote console password")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Only the host may set the remote console password")
      return
   end

   rcon_password_set(password)
   return
end

local function rcon_cmd_parse_list(arg)
   if arg ~= nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "unexpected argument for list remote console command")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "only the host may list authorized remote console users")
      return
   end

   rcon_list()
   return
end

local function rcon_cmd_parse_deauthall(arg)
   if arg ~= nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "unexpected argument for deauthall remote console command")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "only the host may deauthorize remote console users")
      return
   end

   rcon_deauthall()
   return
end

local function rcon_cmd_parse_max_attempts(attempts)
   if attempts == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Expected login attempts count")
      return
   end

   local attempts_int = tonumber(attempts)
   if attempts_int == nil or attempts_int <= 0 then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Login attempts count must be a positive integer")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Only the host may set the maximum login attempts")
      return
   end

   rcon_set_maximum_attempts(attempts_int)
   return
end

local function rcon_cmd_parse_timeout_duration(duration)
   if duration == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Expected timeout duration")
      return
   end

   local duration_int = tonumber(duration)
   if duration_int == nil or duration_int < 0 then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Login timeout duration must be a non-negative integer")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Only the host may set the login timeout duration")
      return
   end

   rcon_set_login_timeout_duration(duration_int)
   return
end

local function rcon_cmd_parse_uuid_lifespan(duration)
   if duration == nil then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Expected UUID lifespan")
      return
   end

   local duration_int = tonumber(duration)
   if duration_int == nil or duration_int <= 0 then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Lifespan must be a positive integer")
      return
   end

   if not network_is_server() then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Only the host may set the UUID lifespan")
      return
   end

   rcon_set_uuid_lifespan(duration_int)
   return
end

local function rcon_cmd_tokenize(message)
   -- splits the message on the first space character
   for i = 1, #message do
      local c = message:sub(i,i)
      if c == ' ' then
         local cmd = message:sub(1,i-1)
         local arg = message:sub(i+1,#message)

         if #arg == 0 then
            arg = nil
         end

         return cmd,arg
      end
   end

   return message,nil
end

local function rcon_cmd_parse(message)
   local cmd, arg = rcon_cmd_tokenize(message)
   
   if #cmd == 0 or cmd == "help" then
      rcon_cmd_parse_help()
   elseif cmd == "login" then
      rcon_cmd_parse_login(arg)
   elseif cmd == "send" then
      rcon_cmd_parse_send(arg)
   elseif cmd == "password" then
      rcon_cmd_parse_password(arg)
   elseif cmd == "list" then
      rcon_cmd_parse_list(arg)
   elseif cmd == "deauthall" then
      rcon_cmd_parse_deauthall(arg)
   elseif cmd == "max-attempts" then
      rcon_cmd_parse_max_attempts(arg)
   elseif cmd == "timeout-duration" then
      rcon_cmd_parse_timeout_duration(arg)
   elseif cmd == "uuid-lifespan" then
      rcon_cmd_parse_uuid_lifespan(arg)
   else
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Unknown remote console command")
   end

   return true
end

hook_chat_command("rcon", "Access the remote console", rcon_cmd_parse)

