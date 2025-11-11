-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
local Config = {
    SHAKey = "4b7e9f2a5d8c1e6b3a9f5d2c7e1b4a8d6c3f9e2b5a8d1c4e7b3a6f9d2e5c8b1a4", -- ! CHANGE ME!
    AESKey = "7f3a9d2e5b8c1f4a6e9d2c5b8f1a4e7d" -- ! CHANGE ME!
}

local Utils = {}
Utils.Events = {}
Utils.Events.nameCache = {}
Utils.Functions = {}
Utils.Notify = {}

Utils.Events.nonceCache = {}
Utils.Events.nonceQueue = {}
Utils.Events.maxNonceCache = 1000

Utils.Notify.Error = function(message)
    print("^1[EVENT-PROTECTION-SYSTEM] Error: " .. message)
end

-- * Creating event names
Utils.Events.CreateEventName = function(name)
    if Utils.Events.nameCache[name] then
        return Utils.Events.nameCache[name]
    end
    local name2sha = sha.hmac(sha.sha256, Config.SHAKey, name)
    Utils.Events.nameCache[name] = name2sha
    return Utils.Events.nameCache[name]
end

-- * Get current timestamp (client/server agnostic)
local function getCurrentTime()
    if IsDuplicityVersion() then
        return os.time()
    else
        return GetCloudTimeAsInt()
    end
end

-- * Generate random nonce (6 hex characters)
local function generateNonce()
    local hex = "0123456789abcdef"
    local nonce = ""
    for i = 1, 6 do
        local rand = math.random(1, 16)
        nonce = nonce .. hex:sub(rand, rand)
    end
    return nonce
end

-- * Add nonce to cache (FIFO queue implementation)
local function addNonceToCache(nonce)
    if Utils.Events.nonceCache[nonce] then
        return false
    end
    
    if #Utils.Events.nonceQueue >= Utils.Events.maxNonceCache then
        local oldestNonce = table.remove(Utils.Events.nonceQueue, 1)
        if oldestNonce then
            Utils.Events.nonceCache[oldestNonce] = nil
        end
    end
    
    table.insert(Utils.Events.nonceQueue, nonce)
    Utils.Events.nonceCache[nonce] = getCurrentTime()
    return true
end

-- * Cleanup old nonces based on timestamp
local function cleanupOldNonces()
    if not IsDuplicityVersion() then
        return
    end
    
    local currentTime = getCurrentTime()
    local removed = 0
    
    for i = #Utils.Events.nonceQueue, 1, -1 do
        local nonce = Utils.Events.nonceQueue[i]
        local timestamp = Utils.Events.nonceCache[nonce]
        
        if timestamp and (currentTime - timestamp > 10) then
            Utils.Events.nonceCache[nonce] = nil
            table.remove(Utils.Events.nonceQueue, i)
            removed = removed + 1
        end
    end
    
    if removed > 0 then
        print("^3[EVENT-PROTECTION-SYSTEM] Cleaned " .. removed .. " old nonces")
    end
end

-- * Validate timestamp and nonce (server-side only)
Utils.Functions.ValidateTimestampAndNonce = function(timestamp, nonce)
    if not IsDuplicityVersion() then
        return true
    end
    
    -- local currentTime = getCurrentTime()
    -- local timeDiff = math.abs(currentTime - timestamp)
    
    -- if timeDiff > 5 then
    --     return false, "Timestamp out of range (replay attack or clock skew)"
    -- end
    
    if Utils.Events.nonceCache[nonce] then
        return false, "Nonce already used (replay attack)"
    end
    
    addNonceToCache(nonce)
    cleanupOldNonces()
    
    return true
end

-- * serializing functions
local function escapeString(str)
    return str:gsub("\\", "\\\\"):gsub("|", "\\|"):gsub(":", "\\:")
end

local function unescapeString(str)
    return str:gsub("\\:", ":"):gsub("\\|", "|"):gsub("\\\\", "\\")
end

local function serializeTable(tbl, depth, seen)
    seen = seen or {}
    
    if seen[tbl] then
        Utils.Notify.Error("Circular reference detected in table")
        return "{}"
    end
    
    if depth > 10 then
        Utils.Notify.Error("Table depth exceeded (max 10)")
        return "{}"
    end
    
    seen[tbl] = true
    
    local parts = {}
    local count = 0
    
    for k, v in pairs(tbl) do
        count = count + 1
        local key = type(k) == "string" and "s" .. escapeString(k) or "d" .. tostring(k)
        local val
        
        if type(v) == "nil" then
            val = "n"
        elseif type(v) == "number" then
            val = "d" .. tostring(v)
        elseif type(v) == "boolean" then
            val = v and "t" or "f"
        elseif type(v) == "string" then
            val = "s" .. escapeString(v)
        elseif type(v) == "table" then
            val = "T" .. serializeTable(v, depth + 1, seen)
        else
            val = "n"
        end
        
        parts[count] = key .. ":" .. val
    end
    
    return "{" .. table.concat(parts, ",") .. "}"
end

local function deserializeTable(str)
    if str == "{}" then return {} end
    
    local result = {}
    local content = str:sub(2, -2)
    
    if content == "" then return result end
    
    local current = ""
    local inEscape = false
    local depth = 0
    
    for i = 1, #content do
        local char = content:sub(i, i)
        
        if char == "\\" and not inEscape then
            inEscape = true
            current = current .. char
        elseif char == "{" then
            depth = depth + 1
            current = current .. char
        elseif char == "}" then
            depth = depth - 1
            current = current .. char
        elseif char == "," and depth == 0 and not inEscape then
            local keyPart, valPart = current:match("^(.-):(.*)")
            if keyPart and valPart then
                local keyType = keyPart:sub(1, 1)
                local keyVal = keyPart:sub(2)
                local valType = valPart:sub(1, 1)
                local valData = valPart:sub(2)
                
                local actualKey
                if keyType == "s" then
                    actualKey = unescapeString(keyVal)
                elseif keyType == "d" then
                    actualKey = tonumber(keyVal)
                    if not actualKey then
                        Utils.Notify.Error("Invalid numeric key: " .. keyVal)
                    end
                end
                
                if actualKey ~= nil then
                    if valType == "n" then
                        result[actualKey] = nil
                    elseif valType == "d" then
                        local numVal = tonumber(valData)
                        if numVal then
                            result[actualKey] = numVal
                        else
                            Utils.Notify.Error("Invalid numeric value: " .. valData)
                        end
                    elseif valType == "t" then
                        result[actualKey] = true
                    elseif valType == "f" then
                        result[actualKey] = false
                    elseif valType == "s" then
                        result[actualKey] = unescapeString(valData)
                    elseif valType == "T" then
                        result[actualKey] = deserializeTable(valData)
                    end
                end
            else
                Utils.Notify.Error("Corrupted key-value pair in table deserialization")
            end
            current = ""
        else
            current = current .. char
            inEscape = false
        end
    end
    
    if current ~= "" then
        local keyPart, valPart = current:match("^(.-):(.*)")
        if keyPart and valPart then
            local keyType = keyPart:sub(1, 1)
            local keyVal = keyPart:sub(2)
            local valType = valPart:sub(1, 1)
            local valData = valPart:sub(2)
            
            local actualKey
            if keyType == "s" then
                actualKey = unescapeString(keyVal)
            elseif keyType == "d" then
                actualKey = tonumber(keyVal)
                if not actualKey then
                    Utils.Notify.Error("Invalid numeric key: " .. keyVal)
                end
            end
            
            if actualKey ~= nil then
                if valType == "n" then
                    result[actualKey] = nil
                elseif valType == "d" then
                    local numVal = tonumber(valData)
                    if numVal then
                        result[actualKey] = numVal
                    else
                        Utils.Notify.Error("Invalid numeric value: " .. valData)
                    end
                elseif valType == "t" then
                    result[actualKey] = true
                elseif valType == "f" then
                    result[actualKey] = false
                elseif valType == "s" then
                    result[actualKey] = unescapeString(valData)
                elseif valType == "T" then
                    result[actualKey] = deserializeTable(valData)
                end
            end
        else
            Utils.Notify.Error("Corrupted key-value pair in table deserialization")
        end
    end
    
    return result
end

Utils.Functions.SerializeArgs = function(tbl)
    local parts = {}
    local count = 0
    
    for k, v in pairs(tbl) do
        count = count + 1
        local key = type(k) == "string" and "s" .. escapeString(k) or "d" .. tostring(k)
        local val
        
        if type(v) == "nil" then
            val = "n"
        elseif type(v) == "number" then
            val = "d" .. tostring(v)
        elseif type(v) == "boolean" then
            val = v and "t" or "f"
        elseif type(v) == "string" then
            val = "s" .. escapeString(v)
        elseif type(v) == "table" then
            local serialized = serializeTable(v, 1, {})
            val = "T" .. serialized
        else
            Utils.Notify.Error("Unsupported type: " .. type(v))
            return nil
        end
        
        parts[count] = key .. ":" .. val
    end
    
    local serializedData = table.concat(parts, "|")
    local timestamp = getCurrentTime()
    local nonce = generateNonce()
    
    return timestamp .. ":" .. nonce .. ":" .. serializedData
end

Utils.Functions.DeserializeArgs = function(serialized)
    if not serialized or serialized == "" then
        Utils.Notify.Error("Empty serialized data")
        return {}
    end
    
    if not serialized:match("^%d+:%w+:") then
        Utils.Notify.Error("Invalid format: missing timestamp/nonce header")
        return {}
    end
    
    local timestamp, nonce, data = serialized:match("^(%d+):(%w+):(.*)")
    
    if not timestamp or not nonce then
        Utils.Notify.Error("Invalid serialized format (missing timestamp or nonce)")
        return {}
    end
    
    timestamp = tonumber(timestamp)
    if not timestamp then
        Utils.Notify.Error("Invalid timestamp value")
        return {}
    end
    
    if IsDuplicityVersion() then
        local valid, error = Utils.Functions.ValidateTimestampAndNonce(timestamp, nonce)
        if not valid then
            Utils.Notify.Error("Security check failed: " .. error)
            return {}
        end
    end
    
    if not data or data == "" then
        return {}
    end
    
    local result = {}
    local current = ""
    local inEscape = false
    local depth = 0
    
    for i = 1, #data do
        local char = data:sub(i, i)
        
        if char == "\\" and not inEscape then
            inEscape = true
            current = current .. char
        elseif char == "{" then
            depth = depth + 1
            current = current .. char
        elseif char == "}" then
            depth = depth - 1
            current = current .. char
        elseif char == "|" and depth == 0 and not inEscape then
            local keyPart, valPart = current:match("^(.-):(.*)")
            if keyPart and valPart then
                local keyType = keyPart:sub(1, 1)
                local keyVal = keyPart:sub(2)
                local valType = valPart:sub(1, 1)
                local valData = valPart:sub(2)
                
                local actualKey
                if keyType == "s" then
                    actualKey = unescapeString(keyVal)
                elseif keyType == "d" then
                    actualKey = tonumber(keyVal)
                    if not actualKey then
                        Utils.Notify.Error("Invalid numeric key: " .. keyVal)
                    end
                end
                
                if actualKey ~= nil then
                    if valType == "n" then
                        result[actualKey] = nil
                    elseif valType == "d" then
                        local numVal = tonumber(valData)
                        if numVal then
                            result[actualKey] = numVal
                        else
                            Utils.Notify.Error("Invalid numeric value: " .. valData)
                        end
                    elseif valType == "t" then
                        result[actualKey] = true
                    elseif valType == "f" then
                        result[actualKey] = false
                    elseif valType == "s" then
                        result[actualKey] = unescapeString(valData)
                    elseif valType == "T" then
                        result[actualKey] = deserializeTable(valData)
                    end
                end
            else
                Utils.Notify.Error("Corrupted key-value pair at position " .. i)
            end
            current = ""
        else
            current = current .. char
            inEscape = false
        end
    end
    
    if current ~= "" then
        local keyPart, valPart = current:match("^(.-):(.*)")
        if keyPart and valPart then
            local keyType = keyPart:sub(1, 1)
            local keyVal = keyPart:sub(2)
            local valType = valPart:sub(1, 1)
            local valData = valPart:sub(2)
            
            local actualKey
            if keyType == "s" then
                actualKey = unescapeString(keyVal)
            elseif keyType == "d" then
                actualKey = tonumber(keyVal)
                if not actualKey then
                    Utils.Notify.Error("Invalid numeric key: " .. keyVal)
                end
            end
            
            if actualKey ~= nil then
                if valType == "n" then
                    result[actualKey] = nil
                elseif valType == "d" then
                    local numVal = tonumber(valData)
                    if numVal then
                        result[actualKey] = numVal
                    else
                        Utils.Notify.Error("Invalid numeric value: " .. valData)
                    end
                elseif valType == "t" then
                    result[actualKey] = true
                elseif valType == "f" then
                    result[actualKey] = false
                elseif valType == "s" then
                    result[actualKey] = unescapeString(valData)
                elseif valType == "T" then
                    result[actualKey] = deserializeTable(valData)
                end
            end
        else
            Utils.Notify.Error("Corrupted final key-value pair")
        end
    end
    
    return result
end

Utils.Events.EncryptMessage = function(...)
    local args = table.pack(...)
    local serializedArgs = Utils.Functions.SerializeArgs(args)
    
    if not serializedArgs then
        Utils.Notify.Error("Serialization failed, cannot encrypt")
        return nil
    end
    
    local success, encryptedData = pcall(aeslua.lua.encrypt, Config.AESKey, serializedArgs, aeslua.lua.AES128, aeslua.lua.CBCMODE)
    
    if not success then
        Utils.Notify.Error("Encryption failed: " .. tostring(encryptedData))
        return nil
    end

    return encryptedData
end

Utils.Events.DecryptMessage = function(encryptedData)
    if not encryptedData or encryptedData == "" then
        Utils.Notify.Error("Empty encrypted data")
        return nil
    end
    
    local success, decryptedData = pcall(aeslua.lua.decrypt, Config.AESKey, encryptedData, aeslua.lua.AES128, aeslua.lua.CBCMODE)
    
    if not success then
        Utils.Notify.Error("Decryption failed: " .. tostring(decryptedData))
        return nil
    end
    
    if not decryptedData or decryptedData == "" then
        Utils.Notify.Error("Decryption returned empty data")
        return nil
    end
    
    local deSerialized = Utils.Functions.DeserializeArgs(decryptedData)
    
    if not deSerialized then
        Utils.Notify.Error("Deserialization failed after decryption")
        return nil
    end
    
    local rawData = table.unpack(deSerialized)
    return rawData
end

exports("encryptMessage", function(...)
    local result = Utils.Events.EncryptMessage(...)
    if not result then
        Utils.Notify.Error("Export encryptMessage failed")
    end
    return result
end)

exports("decryptMessage", function(encryptedData)
    local result = Utils.Events.DecryptMessage(encryptedData)
    if not result then
        Utils.Notify.Error("Export decryptMessage failed")
    end
    return result
end)

exports("CreateEventName", function(name)
    return Utils.Events.CreateEventName(name)
end)