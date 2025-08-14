-- name: Remote Console
-- description: Execute commands as the host remotely.

local function rcon_text_info(message)
   local color = "\\#90f090\\"

   djui_chat_message_create(color .. message)

   return
end

local function rcon_text_warning(message)
   local color = "\\#f0f090\\"

   djui_chat_message_create(color .. message)

   return
end

local function rcon_text_error(message)
   local color = "\\#b02020\\"

   djui_chat_message_create(color .. message)

   return
end

local gHostPlayerIndex = -1;
for _, network_player in ipairs(gNetworkPlayers) do
   if network_player.type == NPT_SERVER then
      gHostPlayerIndex = network_player.localIndex
      break
   end
end

local function rcon_send_packet_to_server(reliable, packet)
   network_send_to(gHostPlayerIndex, reliable, packet)
   return
end

local RCON_PACKET_TYPE_REQUEST_UUID             = 0 -- Sent by client when joining server and requesting UUID
local RCON_PACKET_TYPE_LOGIN                    = 1 -- Sent by client when logging in
local RCON_PACKET_TYPE_SEND                     = 2 -- Sent by client when sending an rcon message
local RCON_PACKET_TYPE_RESPONSE_ERROR_GENERIC   = 0 -- Sent by server when an error occurred
local RCON_PACKET_TYPE_RESPONSE_LOGIN           = 1 -- Sent by server when responding to a login request
local RCON_PACKET_TYPE_RESPONSE_SEND            = 2 -- Sent by server when responding to a send request

local RCON_PACKET_RESPONSE_LOGIN_CODE_OK                 = 0
local RCON_PACKET_RESPONSE_LOGIN_CODE_ALREADY_LOGGED_IN  = 1
local RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD       = 2
local RCON_PACKET_RESPONSE_LOGIN_CODE_FORBIDDEN          = 3

local RCON_PACKET_RESPONSE_SEND_CODE_OK            = 0
local RCON_PACKET_RESPONSE_SEND_CODE_UNAUTHORIZED  = 1

-- Note: we send command packets only to the host.  This is *extremely*
-- important.  If we were to send it to anyone other than the host, then
-- unauthorized players could see private IDs and impersonate us, sniff
-- /rcon login attempts and steal passwords, and watch all /rcon send commands.
-- This is private!!! Do not ever send this information to other players!!!

local function rcon_send_packet_request_uuid(global_index)
   local packet = {
      type = RCON_PACKET_TYPE_REQUEST_UUID,
      global_index = global_index,
   }

   rcon_send_packet_to_server(true, packet)
   return
end

local function rcon_send_packet_login(password)
   local packet = {
      type = RCON_PACKET_TYPE_LOGIN,
      password = password,
   }

   rcon_text_info("Logging into remote console")
   rcon_send_packet_to_server(true, packet)
end

local function rcon_send_packet_send(message)
   local packet = {
      type = RCON_PACKET_TYPE_SEND,
      message = message,
   }

   rcon_text_info("Sending remote console message")
   rcon_send_packet_to_server(true, packet)
end

local function rcon_receive_packet_request_uuid(sender_global_index)
   local sender_local_index = network_local_index_from_global(sender_global_index)

   -- TODO: implement
   rcon_text_info("received UUID request packet from " .. gNetworkPlayers[sender_local_index].name)
   return
end

local function rcon_receive_packet_login(sender, password)
   -- TODO: implement, make sure to use network_send_to(sender, false, ...) for the response
   rcon_text_info("received login packet from " .. sender .. " with password " .. password)
   return
end

local function rcon_receive_packet_send(sender, message)
   -- TODO: implement, make sure to use network_send_to(sender, false, ...) for the response
   rcon_text_info("received send packet from " .. sender .. " with command " .. message)
   return
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

local function rcon_receive_packet_response_login(code)
   if code == RCON_PACKET_RESPONSE_LOGIN_CODE_OK then
      rcon_text_info("Logged into remote console successfully")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_ALREADY_LOGGED_IN then
      rcon_text_warning("You are already authorized with the remote console")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD then
      rcon_text_error("Incorrect password for remote console")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_FORBIDDEN then
      rcon_text_error("You are forbidden from logging into the remote console")
   end

   return
end

local function rcon_receive_packet_response_send(code)
   if code == RCON_PACKET_RESPONSE_SEND_CODE_OK then
      rcon_text_info("Remote console message sent successfully")
   elseif code == RCON_PACKET_RESPONSE_SEND_CODE_UNAUTHORIZED then
      rcon_text_error("Unauthorized to send remote console messages")
   end

   return
end

local function rcon_receive_packet_response_generic_error()
   -- These are received when we don't want to notify the client of the specifc
   -- cause of the error.  This is useful when invalid data is sent, which may
   -- come from hacking attempts.  If the client is trying to hack us, we want
   -- to be as vague as possible, so we just send a generic error packet.
   rcon_text_error("A remote console error occurred.  Please try again later, or rejoin if the issue persists.")
   return
end

local function rcon_packet_receive_server(packet)
   -- TODO: store/receive private UUIDs for each client and associate them in a
   -- map to prevent attackers from impersonating authorized users by modifying
   -- the player ID.
   local sender = "[UNKNOWN]"

   if packet.type == RCON_PACKET_TYPE_LOGIN then
      rcon_receive_packet_login(sender, packet.password)
   elseif packet.type == RCON_PACKET_TYPE_SEND then
      rcon_receive_packet_send(sender, packet.message)
   elseif packet.type == RCON_PACKET_TYPE_REQUEST_UUID then
      rcon_receive_packet_request_uuid(packet.global_index)
   end

   return
end

local function rcon_packet_receive_client(packet)
   if packet.type == RCON_PACKET_TYPE_RESPONSE_LOGIN then
      rcon_receive_packet_response_login(packet.code)
   elseif packet.type == RCON_PACKET_TYPE_RESPONSE_SEND then
      rcon_receive_packet_response_send(packet.code)
   elseif packet.type == RCON_PACKET_TYPE_RESPONSE_ERROR_GENERIC then
      rcon_receive_packet_response_generic_error()
   end

   return
end

local function rcon_packet_receive(packet)
   if network_is_server() then
      rcon_packet_receive_server(packet)
      return
   end

   rcon_packet_receive_client(packet)
   return
end

local function rcon_join_game()
   local global_index = network_global_index_from_local(0)

   rcon_send_packet_request_uuid(global_index)
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

hook_event(HOOK_ON_PACKET_RECEIVE, rcon_packet_receive)
hook_event(HOOK_JOINED_GAME, rcon_join_game)
hook_chat_command("rcon", "Access the remote console", rcon_parse_cmd)

