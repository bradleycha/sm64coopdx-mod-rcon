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

local RCON_LOG_PREFIX = "rcon: "

local function rcon_log_info(message)
   log_to_console(RCON_LOG_PREFIX .. message, CONSOLE_MESSAGE_INFO)
end

local function rcon_log_warning(message)
   log_to_console(RCON_LOG_PREFIX .. message, CONSOLE_MESSAGE_WARNING)
end

local function rcon_log_error(message)
   log_to_console(RCON_LOG_PREFIX .. message, CONSOLE_MESSAGE_ERROR)
end

local gRconHostPlayerIndex = -1;
for _, network_player in ipairs(gNetworkPlayers) do
   if network_player.type == NPT_SERVER then
      gRconHostPlayerIndex = network_player.localIndex
      break
   end
end

local function rcon_format_player_name(local_index)
   local player = gNetworkPlayers[local_index]

   local name = player.name .. " [" .. local_index .. "]"

   local coopnet_id = get_coopnet_id(local_index)
   if coopnet_id ~= "-1" then
      name = name .. " [" .. coopnet_id .. "]"
   end

   return name
end

local function rcon_receive_packet_from_server(packet)
   -- TODO: implement packet decryption
   return packet
end

local function rcon_receive_packet_from_client(packet)
   -- TODO: implement packet decryption
   return packet
end

local function rcon_send_packet_to_server(packet)
   -- TODO: implement packet encryption
   network_send_to(gRconHostPlayerIndex, true, packet)
   return
end

local function rcon_send_packet_to_client(local_index, packet)
   -- TODO: implement packet encryption
   network_send_to(local_index, true, packet)
   return
end

-- Stores all player information, except for gNetworkPlayers[0], which is the host
local gRconPlayerTable = {}
gRconPlayerTable[MAX_PLAYERS - 1] = nil

local function rcon_uuid_to_local_index(uuid)
   for i, player in ipairs(gRconPlayerTable) do
      if player ~= nil and player.valid then
         if player.uuid == uuid then
            return i
         end
      end
   end

   return -1
end

local function rcon_uuid_exists_for_local_index(local_index)
   local player = gRconPlayerTable[local_index]
   return player ~= nil and player.valid
end

local function rcon_uuid_generate()
   return math.random(0, math.maxinteger)
end

local function rcon_uuid_create_new(local_index)
   local uuid = rcon_uuid_generate(local_index)

   gRconPlayerTable[local_index] = {
      valid = true,
      uuid = uuid,
      failed_login_attempts = 0,
      forbidden = false,
      access = false,
   }

   rcon_log_info("assigned UUID " .. tostring(uuid) .. " to player " .. rcon_format_player_name(local_index))
   return uuid
end

local function rcon_uuid_remove(local_index)
   if not rcon_uuid_exists_for_local_index(local_index) then
      return
   end

   rcon_log_info("removing UUID for player " .. rcon_format_player_name(local_index))
   gRconPlayerTable[local_index].valid = false
   return
end

local gRconClientUuid = -1;
local function rcon_uuid_store(assigned_uuid)
   gRconClientUuid = assigned_uuid
   return
end

local function rcon_uuid_get()
   return gRconClientUuid
end

local RCON_PACKET_TYPE_REQUEST_UUID             = 0 -- Sent by client when joining server and requesting UUID
local RCON_PACKET_TYPE_LOGIN                    = 1 -- Sent by client when logging in
local RCON_PACKET_TYPE_SEND                     = 2 -- Sent by client when sending an rcon message
local RCON_PACKET_TYPE_RESPONSE_ERROR_GENERIC   = 0 -- Sent by server when an error occurred
local RCON_PACKET_TYPE_RESPONSE_REQUEST_UUID    = 1 -- Sent by server when a UUID is assigned to a client
local RCON_PACKET_TYPE_RESPONSE_LOGIN           = 2 -- Sent by server when responding to a login request
local RCON_PACKET_TYPE_RESPONSE_SEND            = 3 -- Sent by server when responding to a send request
local RCON_PACKET_TYPE_DEAUTHORIZED             = 4 -- Sent by server when a player has been deauthorized

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

   rcon_send_packet_to_server(packet)
   return
end

local function rcon_send_packet_login(password)
   local packet = {
      uuid = rcon_uuid_get(),
      type = RCON_PACKET_TYPE_LOGIN,
      password = password,
   }

   rcon_text_info("Logging into remote console")
   rcon_send_packet_to_server(packet)
end

local function rcon_send_packet_send(message)
   local packet = {
      uuid = rcon_uuid_get(),
      type = RCON_PACKET_TYPE_SEND,
      message = message,
   }

   rcon_text_info("Sending remote console message")
   rcon_send_packet_to_server(packet)
end

local function rcon_receive_packet_request_uuid(sender_global_index)
   local sender_local_index = network_local_index_from_global(sender_global_index)

   -- Don't allow UUIDs to be regenerated, as that could be used by an attacker
   -- to deauthorize existing users.  Combined with a script to spam packets,
   -- this could effectively disable the rcon for everyone in the server.
   if rcon_uuid_exists_for_local_index(sender_local_index) then
      rcon_log_warning("attempted to regenerate UUID for player " .. rcon_format_player_name(sender_local_index))
      rcon_send_packet_to_client(sender_local_index, {type = RCON_PACKET_TYPE_RESPONSE_ERROR_GENERIC})
      return
   end

   local assigned_uuid = rcon_uuid_create_new(sender_local_index)

   rcon_send_packet_to_client(sender_local_index, {
      type = RCON_PACKET_TYPE_RESPONSE_REQUEST_UUID,
      assigned_uuid = assigned_uuid
   })

   return
end

local RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS   = "rcon_maximum_login_attempts"
local RCON_SAVE_KEY_PASSWORD_HASH            = "rcon_password_hash"
local RCON_SAVE_KEY_PASSWORD_SALT            = "rcon_password_salt"

local gRconMaximumLoginAttempts = 5
if mod_storage_exists(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS) then
   gRconMaximumLoginAttempts = mod_storage_load_number(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS)
end

local gRconPasswordHash = nil
if mod_storage_exists(RCON_SAVE_KEY_PASSWORD_HASH) then
   gRconPasswordHash = mod_storage_load(RCON_SAVE_KEY_PASSWORD_HASH)
end

local gRconPasswordSalt = nil
if mod_storage_exists(RCON_SAVE_KEY_PASSWORD_SALT) then
   gRconPasswordSalt = mod_storage_load(RCON_SAVE_KEY_PASSWORD_SALT)
end

local function rcon_salt_and_hash_password(password, salt)
   local password_salted = password .. salt

   -- TODO: implement hashing, this will require extending the lua API to
   -- provide cryptographic functions, particularly one of the SHA2 functions.
   -- right now, if your rcon.sav file gets leaked, your password is out in the
   -- open for attackers to steal.  please implement this!
   return password_salted
end

local function rcon_check_password(password)
   if gRconPasswordHash == nil then
      rcon_log_error("missing password hash value from save file, unable to verify password")
      return false
   end
   if gRconPasswordSalt == nil then
      rcon_log_error("missing password salt value from save file, unable to verify password")
      return false
   end

   local hash = rcon_salt_and_hash_password(password, gRconPasswordSalt)

   return hash == gRconPasswordHash
end

local RCON_PASSWORD_SALT_CHARACTERS = 16

local function rcon_generate_password_salt()
   -- TODO: use random characters for more variety, thus security
   return tostring(math.random(0, math.maxinteger))
end

local function rcon_set_password(password)
   local salt = rcon_generate_password_salt()
   local hash = rcon_salt_and_hash_password(password, salt)

   gRconPasswordHash = hash
   gRconPasswordSalt = salt

   mod_storage_save(RCON_SAVE_KEY_PASSWORD_HASH, hash)
   mod_storage_save(RCON_SAVE_KEY_PASSWORD_SALT, salt)

   local log_message = "Set password to \'" .. hash .. "\' with salt \'" .. salt .. "\'"
   rcon_log_info(log_message)
   rcon_text_info(log_message)

   return
end

local function rcon_deauthall()
   for i, player in ipairs(gRconPlayerTable) do
      if player.valid and player.access then
         player.access = false
         rcon_send_packet_to_client(i, {
            type = RCON_PACKET_TYPE_DEAUTHORIZED,
         })

         local name = rcon_format_player_name(i)
         local log_message = "Deauthorizing player " .. name
         rcon_log_info(log_message)
         rcon_text_info(log_message)
      end
   end
   
   return
end

local function rcon_set_maximum_attempts(attempts)
   gRconMaximumLoginAttempts = attempts

   mod_storage_save_number(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS, attempts)

   local log_message = "Set maximum login attempts to " .. tostring(attempts)
   rcon_log_info(log_message)
   rcon_text_info(log_message)

   return
end

local function rcon_receive_packet_login(sender, password)
   local player = gRconPlayerTable[sender]
   local name = rcon_format_player_name(sender)

   if player.access then
      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
         code = RCON_PACKET_RESPONSE_LOGIN_CODE_ALREADY_LOGGED_IN,
      })
      return
   end

   if player.forbidden then
      local log_message = "Forbidden player " .. name .. " attempted to login to the remote console"
      rcon_log_warning(log_message)
      rcon_text_warning(log_message)

      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
         code = RCON_PACKET_RESPONSE_LOGIN_CODE_FORBIDDEN,
      })
      return
   end

   local password_is_correct = rcon_check_password(password)

   if password_is_correct then
      local log_message = "Player " .. name .. " successfully logged into the remote console"
      rcon_log_info(log_message)
      rcon_text_info(log_message)
      
      player.access = true
      player.failed_login_attempts = 0

      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
         code = RCON_PACKET_RESPONSE_LOGIN_CODE_OK,
      })
      return
   end

   player.failed_login_attempts = player.failed_login_attempts + 1

   local log_message = "Player " .. name .. " attempted to login to the remote console with incorrect password \'" .. password .. "\', they have " .. tostring(gRconMaximumLoginAttempts - player.failed_login_attempts) .. " login attempts remaining"
   rcon_log_warning(log_message)
   rcon_text_warning(log_message)

   if player.failed_login_attempts >= gRconMaximumLoginAttempts then
      local log_message = "Player " .. name .. " surpassed maximum number of invalid login attempts, forbidding future login attempts"
      rcon_log_warning(log_message)
      rcon_text_warning(log_message)

      player.forbidden = true
   end

   rcon_send_packet_to_client(sender, {
      type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
      code = RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD,
   })
   return
end

local function rcon_receive_packet_send(sender, message)
   local player = gRconPlayerTable[sender]
   local name = rcon_format_player_name(sender)

   if not player.access then
      local log_message = "Unauthorized player " .. name .. " attempted to send remote console message \'" .. message .. "\'"
      rcon_log_warning(log_message)
      rcon_text_warning(log_message)

      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_SEND,
         code = RCON_PACKET_RESPONSE_SEND_CODE_UNAUTHORIZED,
      })
      return
   end

   local log_message = "Player " .. name .. " sent remote console message \'" .. message .. "\'"
   rcon_log_info(log_message)
   rcon_text_info(log_message)

   -- Custom lua function, requires patching the game's sources
   send_chat_message(message)
   
   rcon_send_packet_to_client(sender, {
      type = RCON_PACKET_TYPE_RESPONSE_SEND,
      code = RCON_PACKET_RESPONSE_SEND_CODE_OK,
   })

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

local function rcon_receive_packet_response_request_uuid(assigned_uuid)
   rcon_uuid_store(assigned_uuid)
   return
end

local function rcon_receive_packet_deauthorized()
   rcon_text_warning("You have been deauthorized from the remote console")
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

local function rcon_packet_receive_server_uuid(packet)
   local sender = rcon_uuid_to_local_index(packet.uuid)
   if sender == -1 then
      rcon_log_warning("received packet with invalid UUID " .. packet.uuid)
      return
   end

   if packet.type == RCON_PACKET_TYPE_LOGIN then
      rcon_receive_packet_login(sender, packet.password)
   elseif packet.type == RCON_PACKET_TYPE_SEND then
      rcon_receive_packet_send(sender, packet.message)
   end

   return
end

local function rcon_packet_receive_server(packet)
   if packet.type == RCON_PACKET_TYPE_REQUEST_UUID then
      rcon_receive_packet_request_uuid(packet.global_index)
      return
   end

   rcon_packet_receive_server_uuid(packet)
end

local function rcon_packet_receive_client(packet)
   if packet.type == RCON_PACKET_TYPE_RESPONSE_LOGIN then
      rcon_receive_packet_response_login(packet.code)
   elseif packet.type == RCON_PACKET_TYPE_RESPONSE_SEND then
      rcon_receive_packet_response_send(packet.code)
   elseif packet.type == RCON_PACKET_TYPE_RESPONSE_REQUEST_UUID then
      rcon_receive_packet_response_request_uuid(packet.assigned_uuid)
   elseif packet.type == RCON_PACKET_TYPE_DEAUTHORIZED then
      rcon_receive_packet_deauthorized()
   elseif packet.type == RCON_PACKET_TYPE_RESPONSE_ERROR_GENERIC then
      rcon_receive_packet_response_generic_error()
   end

   return
end

local function rcon_packet_receive(packet)
   if network_is_server() then
      rcon_packet_receive_server(rcon_receive_packet_from_server(packet))
      return
   end

   rcon_packet_receive_client(rcon_receive_packet_from_client(packet))
   return
end

local function rcon_join_game()
   local global_index = network_global_index_from_local(0)

   rcon_send_packet_request_uuid(global_index)
   return
end

local function rcon_player_disconnected(mario_state)
   if not network_is_server() then
      return
   end

   -- I don't know why they don't pass the local index of the player who left,
   -- so we have to find it manually...
   for i, network_player in ipairs(gNetworkPlayers) do
      if not network_player.connected then
         rcon_uuid_remove(i)
      end
   end

   return
end

local function rcon_parse_cmd_help()
   djui_chat_message_create(
      "\\#f0a0a0\\Remote console command list:\n" ..
      "\\#a0a0a0\\   help\\#ffffff\\ - Display the help menu\n" ..
      "\\#a0a0a0\\   login \\#9090f0\\[password]\\#ffffff\\ - Authenticate with the server to get remote console privilege\n" ..
      "\\#a0a0a0\\   send \\#9090f0\\[message]\\#ffffff\\ - Remotely send a chat message as the host\n" ..
      "\\#a0a0a0\\   password \\#9090f0\\[password]\\#ffffff\\ - Set the remote console password\n" ..
      "\\#a0a0a0\\   deauthall\\#ffffff\\ - Deauthorize all players from the remote console\n" ..
      "\\#a0a0a0\\   max-attempts \\#9090f0\\[count]\\#ffffff\\ - Set the maximum allowed number of login attempts"
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

local function rcon_parse_cmd_deauthall(arg)
   if arg ~= nil then
      rcon_text_error("Unexpected argument for deauthall remote console command")
      return
   end

   if not network_is_server() then
      rcon_text_error("Only the host may deauthorize remote console users")
      return
   end

   rcon_deauthall()
   return
end

local function rcon_parse_cmd_max_attempts(attempts)
   if attempts == nil then
      rcon_text_error("Expected login attempts count")
      return
   end

   local attempts_int = tonumber(attempts)
   if attempts_int == nil or attempts_int <= 0 then
      rcon_text_error("Login attempts count must be a positive integer")
      return
   end

   if not network_is_server() then
      rcon_text_error("Only the host may set the maximum login attempts")
      return
   end

   rcon_set_maximum_attempts(attempts_int)
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
   elseif cmd == "deauthall" then
      rcon_parse_cmd_deauthall(arg)
   elseif cmd == "max-attempts" then
      rcon_parse_cmd_max_attempts(arg)
   else
      rcon_text_error("Unknown remote console command")
   end

   return true
end

hook_event(HOOK_ON_PACKET_RECEIVE, rcon_packet_receive)
hook_event(HOOK_JOINED_GAME, rcon_join_game)
hook_event(HOOK_ON_PLAYER_DISCONNECTED, rcon_player_disconnected)
hook_chat_command("rcon", "Access the remote console", rcon_parse_cmd)

