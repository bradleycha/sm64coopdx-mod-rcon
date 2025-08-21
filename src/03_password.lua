-- Copyright (c) Chase Bradley 2025
-- src/password.lua: password hasher and checker

local gRconPasswordHash = nil
if mod_storage_exists(RCON_SAVE_KEY_PASSWORD_HASH) then
   gRconPasswordHash = rcon_utils_base16_decode(mod_storage_load(RCON_SAVE_KEY_PASSWORD_HASH))
end

local gRconPasswordSalt = nil
if mod_storage_exists(RCON_SAVE_KEY_PASSWORD_SALT) then
   gRconPasswordSalt = rcon_utils_base16_decode(mod_storage_load(RCON_SAVE_KEY_PASSWORD_SALT))
end

local function rcon_password_salt_and_hash(password, salt)
   local password_salted = password .. salt

   -- Custom native function
   local password_hashed = crypto_hash_sha256(password_salted)

   return password_hashed
end

local function rcon_password_check(password)
   if gRconPasswordHash == nil then
      rcon_log_console(RCON_LOG_ERROR, "missing password hash value from save file, unable to verify password")
      return false
   end
   if gRconPasswordSalt == nil then
      rcon_log_console(RCON_LOG_ERROR, "missing password salt value from save file, unable to verify password")
      return false
   end

   local hash = rcon_password_salt_and_hash(password, gRconPasswordSalt)

   return hash == gRconPasswordHash
end

local RCON_PASSWORD_SALT_BYTES = 16

local function rcon_password_salt_generate()
   local salt = ""

   for _ = 1, RCON_PASSWORD_SALT_BYTES do
      salt = salt .. string.char(math.random(0, 255))
   end

   return salt
end

local function rcon_password_set(password)
   local salt = rcon_password_salt_generate()
   local hash = rcon_password_salt_and_hash(password, salt)

   gRconPasswordHash = hash
   gRconPasswordSalt = salt

   local hash_base16 = rcon_utils_base16_encode(hash)
   local salt_base16 = rcon_utils_base16_encode(salt)

   mod_storage_save(RCON_SAVE_KEY_PASSWORD_HASH, hash_base16)
   mod_storage_save(RCON_SAVE_KEY_PASSWORD_SALT, salt_base16)

   local log_message = "Set password hash to \'" .. hash_base16 .. "\' with salt \'" .. salt_base16 .. "\'"
   rcon_log_all(RCON_LOG_LEVEL_DEBUG, log_message)

   return
end

