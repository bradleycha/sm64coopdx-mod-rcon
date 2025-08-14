-- name: Remote Console
-- description: Execute commands as the host remotely.

local function rcon_text_info(message)
   local color = "\\#90f090\\"

   djui_chat_message_create(color .. message)

   return
end

local function rcon_text_error(message)
   local color = "\\#b02020\\"

   djui_chat_message_create(color .. message)

   return
end

local function rcon_send_packet_login(password)
   -- TODO: implement
   rcon_text_info("login with password " .. password)
end

local function rcon_send_packet_send(cmd)
   -- TODO: implement
   rcon_text_info("send command " .. cmd)
end

local function rcon_set_password(password)
   -- TODO: implement
   rcon_text_info("set password to " .. password)
end

local function rcon_deauth()
   -- TODO: implement
   rcon_text_info("deauthorize all users")
   return
end

local function rcon_parse_cmd_help()
   djui_chat_message_create(
      "\\#f0a0a0\\Remote console command list:\n" ..
      "\\#a0a0a0\\   help\\#ffffff\\ - Display the help menu\n" ..
      "\\#a0a0a0\\   login \\#9090f0\\[password]\\#ffffff\\ - Authenticate with the server to get remote console privilege\n" ..
      "\\#a0a0a0\\   send \\#9090f0\\[message]\\#ffffff\\ - Remotely send a chat message as the host\n" ..
      "\\#a0a0a0\\   password \\#9090f0\\[password]\\#ffffff\\ - Set the remote console password\n" ..
      "\\#a0a0a0\\   deauth\\#ffffff\\ - Deauthorize all players from the remote console"
   )

   return
end

local function rcon_parse_cmd_login(password)
   if password == nil then
      rcon_text_error("Missing remote console password")
      return
   end

   if network_is_server() then
      rcon_text_error("You are the host, refusing to login")
      return
   end

   rcon_send_packet_login(password)
   return
end

local function rcon_parse_cmd_send(cmd)
   if cmd == nil then
      rcon_text_error("Missing remote chat message")
      return
   end

   if network_is_server() then
      rcon_text_error("You are the host, refusing to send message")
      return
   end

   rcon_send_packet_send(cmd)
   return
end

local function rcon_parse_cmd_password(password)
   if password == nil then
      rcon_text_error("Missing new remote console password")
      return
   end

   if not network_is_server() then
      rcon_text_error("Only the host may set the remote console password")
      return
   end

   rcon_set_password(password)
   return
end

local function rcon_parse_cmd_deauth(arg)
   if arg ~= nil then
      rcon_text_error("Unexpected argument for deauth remote console command")
      return
   end

   if not network_is_server() then
      rcon_text_error("Only the host may deauthorize remote console users")
      return
   end

   rcon_deauth()
   return
end

local function rcon_tokenize_cmd(message)
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

local function rcon_parse_cmd(message)
   local cmd, arg = rcon_tokenize_cmd(message)
   
   if #cmd == 0 or cmd == "help" then
      rcon_parse_cmd_help()
   elseif cmd == "login" then
      rcon_parse_cmd_login(arg)
   elseif cmd == "send" then
      rcon_parse_cmd_send(arg)
   elseif cmd == "password" then
      rcon_parse_cmd_password(arg)
   elseif cmd == "deauth" then
      rcon_parse_cmd_deauth(arg)
   else
      rcon_text_error("Unknown remote console command")
   end

   return true
end

hook_chat_command("rcon", "Access the remote console", rcon_parse_cmd)

