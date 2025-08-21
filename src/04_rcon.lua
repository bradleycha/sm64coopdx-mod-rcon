-- Copyright (c) Chase Bradley 2025
-- src/rcon.lua: main rcon logic



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
      timestamp_last_login_attempt = -1,
      timestamp_last_uuid = get_time(),
   }

   rcon_log_console(RCON_LOG_LEVEL_DEBUG, "assigned UUID " .. tostring(uuid) .. " to player " .. rcon_format_player_name(local_index))
   return uuid
end

local function rcon_uuid_remove(local_index)
   if not rcon_uuid_exists_for_local_index(local_index) then
      return
   end

   rcon_log_console(RCON_LOG_LEVEL_DEBUG, "removing UUID for player " .. rcon_format_player_name(local_index))
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
local RCON_PACKET_TYPE_MESSAGE                  = 5 -- Sent by server when a message should be displayed on the client

local RCON_PACKET_RESPONSE_LOGIN_CODE_OK                 = 0
local RCON_PACKET_RESPONSE_LOGIN_CODE_ALREADY_LOGGED_IN  = 1
local RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD       = 2
local RCON_PACKET_RESPONSE_LOGIN_CODE_THROTTLE           = 3

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

   rcon_log_textbox(RCON_LOG_LEVEL_INFO, "Logging into remote console")
   rcon_send_packet_to_server(packet)
end

local function rcon_send_packet_send(message)
   local packet = {
      uuid = rcon_uuid_get(),
      type = RCON_PACKET_TYPE_SEND,
      message = message,
   }

   rcon_log_textbox(RCON_LOG_LEVEL_INFO, "Sending remote console message")
   rcon_send_packet_to_server(packet)
end

local function rcon_send_packet_message(sender, level, message)
   local packet = {
      type = RCON_PACKET_TYPE_MESSAGE,
      level = level,
      message = message,
   }

   for i, player in ipairs(gRconPlayerTable) do
      if player ~= nil and player.valid and player.access and i ~= sender then
         rcon_send_packet_to_client(i, packet)
      end
   end

   return
end

local function rcon_receive_packet_request_uuid(sender_global_index)
   local sender_local_index = network_local_index_from_global(sender_global_index)

   -- Don't allow UUIDs to be regenerated, as that could be used by an attacker
   -- to deauthorize existing users.  Combined with a script to spam packets,
   -- this could effectively disable the rcon for everyone in the server.
   if rcon_uuid_exists_for_local_index(sender_local_index) then
      local log_message = "attempted to regenerate UUID for player " .. rcon_format_player_name(sender_local_index)
      rcon_log_console(RCON_LOG_LEVEL_WARNING, log_message)
      rcon_send_packet_message(sender_local_index, log_message)
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


local function rcon_receive_packet_message(level, message)
   rcon_log_textbox(level, message)
   return
end

local gRconMaximumLoginAttempts = 5
if mod_storage_exists(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS) then
   gRconMaximumLoginAttempts = mod_storage_load_number(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS)
end

local gRconLoginTimeoutDuration = 3
if mod_storage_exists(RCON_SAVE_KEY_LOGIN_TIMEOUT_DURATION) then
   gRconLoginTimeoutDuration = mod_storage_load_number(RCON_SAVE_KEY_LOGIN_TIMEOUT_DURATION)
end

local gRconUuidLifespan = 60
if mod_storage_exists(RCON_SAVE_KEY_UUID_LIFESPAN) then
   gRconUuidLifespan = mod_storage_load_number(RCON_SAVE_KEY_UUID_LIFESPAN)
end

local function rcon_list()
   local listed = false

   for i, player in ipairs(gRconPlayerTable) do
      if player ~= nil and player.valid and player.access then
         listed = true

         local name = rcon_format_player_name(i)
         rcon_log_textbox(RCON_LOG_LEVEL_INFO, name)
      end
   end

   if not listed then
      rcon_log_textbox(RCON_LOG_LEVEL_WARNING, "There are no players currently logged into the remote console")
   end
   
   return
end

local function rcon_deauthall()
   for i, player in ipairs(gRconPlayerTable) do
      if player ~= nil and player.valid and player.access then
         player.access = false
         rcon_send_packet_to_client(i, {
            type = RCON_PACKET_TYPE_DEAUTHORIZED,
         })

         local name = rcon_format_player_name(i)
         local log_message = "Deauthorizing player " .. name
         rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)
      end
   end
   
   return
end

local function rcon_set_maximum_attempts(attempts)
   gRconMaximumLoginAttempts = attempts

   mod_storage_save_number(RCON_SAVE_KEY_MAXIMUM_LOGIN_ATTEMPTS, attempts)

   local log_message = "Set maximum login attempts to " .. tostring(attempts)
   rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)

   return
end

local function rcon_set_login_timeout_duration(duration)
   gRconLoginTimeoutDuration = duration

   mod_storage_save_number(RCON_SAVE_KEY_LOGIN_TIMEOUT_DURATION, duration)

   local log_message = "Set login timeout duration to " .. tostring(duration) .. " seconds"
   rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)

   return
end

local function rcon_set_uuid_lifespan(duration)
   gRconUuidLifespan = duration

   mod_storage_save_number(RCON_SAVE_KEY_UUID_LIFESPAN, duration)

   local log_message = "Set UUID lifespan to " .. tostring(duration) .. " seconds"
   rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)

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

   local timestamp_prev = player.timestamp_last_login_attempt
   local timestamp_curr = get_time()
   if timestamp_prev ~= -1 then
      local duration = timestamp_curr - timestamp_prev

      if duration < gRconLoginTimeoutDuration then
         local log_message = "Player " .. name .. " attempted to login too quickly (" .. tostring(duration) ..  " seconds) after a previously failed login attempt"
         rcon_log_all(RCON_LOG_LEVEL_WARNING, log_message)
         rcon_send_packet_message(sender, RCON_LOG_LEVEL_WARNING, log_message)

         rcon_send_packet_to_client(sender, {
            type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
            code = RCON_PACKET_RESPONSE_LOGIN_CODE_THROTTLE,
         })
         return
      end
   end
   player.timestamp_last_login_attempt = timestamp_curr

   if player.forbidden then
      local log_message = "Forbidden player " .. name .. " attempted to login to the remote console with password \'" .. password .. "\'"
      rcon_log_all(RCON_LOG_LEVEL_WARNING, log_message)
      rcon_send_packet_message(sender, RCON_LOG_LEVEL_WARNING, log_message)

      -- If someone is trying to brute force the password, we lie to them and
      -- claim the password is incorrect, even if they get it correct this time.
      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
         code = RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD,
      })
      return
   end

   local password_is_correct = rcon_password_check(password)

   if password_is_correct then
      local log_message = "Player " .. name .. " successfully logged into the remote console"
      rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)
      rcon_send_packet_message(sender, RCON_LOG_LEVEL_INFO, log_message)
      
      player.access = true
      player.failed_login_attempts = 0
      player.timestamp_last_login_attempt = -1

      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_LOGIN,
         code = RCON_PACKET_RESPONSE_LOGIN_CODE_OK,
      })
      return
   end

   player.failed_login_attempts = player.failed_login_attempts + 1

   local log_message = "Player " .. name .. " attempted to login to the remote console with incorrect password \'" .. password .. "\', they have " .. tostring(gRconMaximumLoginAttempts - player.failed_login_attempts) .. " login attempts remaining"
   rcon_log_all(RCON_LOG_LEVEL_WARNING, log_message)
   rcon_send_packet_message(sender, RCON_LOG_LEVEL_WARNING, log_message)

   if player.failed_login_attempts >= gRconMaximumLoginAttempts then
      local log_message = "Player " .. name .. " surpassed maximum number of invalid login attempts, forbidding future login attempts"
      rcon_log_all(RCON_LOG_LEVEL_WARNING, log_message)
      rcon_send_packet_message(sender, RCON_LOG_LEVEL_WARNING, log_message)

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
      rcon_log_all(RCON_LOG_LEVEL_WARNING, log_message)
      rcon_send_packet_message(sender, RCON_LOG_LEVEL_WARNING, log_message)

      rcon_send_packet_to_client(sender, {
         type = RCON_PACKET_TYPE_RESPONSE_SEND,
         code = RCON_PACKET_RESPONSE_SEND_CODE_UNAUTHORIZED,
      })
      return
   end

   local log_message = "Player " .. name .. " sent remote console message \'" .. message .. "\'"
   rcon_log_all(RCON_LOG_LEVEL_INFO, log_message)
   rcon_send_packet_message(sender, RCON_LOG_LEVEL_INFO, log_message)

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
      rcon_log_textbox(RCON_LOG_LEVEL_INFO, "Logged into remote console successfully")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_ALREADY_LOGGED_IN then
      rcon_log_textbox(RCON_LOG_LEVEL_WARNING, "You are already authorized with the remote console")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_BAD_PASSWORD then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Incorrect password for remote console")
   elseif code == RCON_PACKET_RESPONSE_LOGIN_CODE_THROTTLE then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Please wait longer until the next login attempt")
   end

   return
end

local function rcon_receive_packet_response_send(code)
   if code == RCON_PACKET_RESPONSE_SEND_CODE_OK then
      rcon_log_textbox(RCON_LOG_LEVEL_INFO, "Remote console message sent successfully")
   elseif code == RCON_PACKET_RESPONSE_SEND_CODE_UNAUTHORIZED then
      rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "Unauthorized to send remote console messages")
   end

   return
end

local function rcon_receive_packet_response_request_uuid(assigned_uuid)
   rcon_uuid_store(assigned_uuid)
   return
end

local function rcon_receive_packet_deauthorized()
   rcon_log_textbox(RCON_LOG_LEVEL_WARNING, "You have been deauthorized from the remote console")
   return
end

local function rcon_receive_packet_response_generic_error()
   -- These are received when we don't want to notify the client of the specifc
   -- cause of the error.  This is useful when invalid data is sent, which may
   -- come from hacking attempts.  If the client is trying to hack us, we want
   -- to be as vague as possible, so we just send a generic error packet.
   rcon_log_textbox(RCON_LOG_LEVEL_ERROR, "A remote console error occurred.  Please try again later, or rejoin if the issue persists.")
   return
end

local function rcon_packet_receive_server_uuid(packet)
   local sender = rcon_uuid_to_local_index(packet.uuid)
   if sender == -1 then
      rcon_log_console(RCON_LOG_LEVEL_WARNING, "received packet with invalid UUID " .. packet.uuid)
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
   elseif packet.type == RCON_PACKET_TYPE_MESSAGE then
      rcon_receive_packet_message(packet.level, packet.message)
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

local function rcon_update_player(local_index, timestamp)
   local player = gRconPlayerTable[local_index]
   local name = rcon_format_player_name(local_index)

   local time_since_last_uuid = timestamp - player.timestamp_last_uuid
   if time_since_last_uuid >= gRconUuidLifespan then
      player.timestamp_last_uuid = timestamp

      local uuid = rcon_uuid_generate()

      rcon_log_console(RCON_LOG_LEVEL_DEBUG, "Assigning new UUID " .. tostring(uuid) .. " to " .. name)

      player.uuid = uuid

      rcon_send_packet_to_client(local_index, {
         type = RCON_PACKET_TYPE_RESPONSE_REQUEST_UUID,
         assigned_uuid = uuid
      })
   end

   return
end

function rcon_update()
   local time = get_time()

   for i, player in ipairs(gRconPlayerTable) do
      if player ~= nil and player.valid then
         rcon_update_player(i, time)
      end
   end

   return
end

hook_event(HOOK_ON_PACKET_RECEIVE, rcon_packet_receive)
hook_event(HOOK_JOINED_GAME, rcon_join_game)
hook_event(HOOK_ON_PLAYER_DISCONNECTED, rcon_player_disconnected)
hook_event(HOOK_UPDATE, rcon_update)

