Utils = {}
Utils.Events = {}
Utils.Events.nameCache = {}
Utils.Functions = {}
Utils.Notify = {}

-- Nonce cache for replay attack prevention
Utils.Events.nonceCache = {}
Utils.Events.nonceCacheSize = 0
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

-- * Add nonce to cache (FIFO when full)
local function addNonceToCache(nonce)
    if Utils.Events.nonceCache[nonce] then
        return false
    end
    
    if Utils.Events.nonceCacheSize >= Utils.Events.maxNonceCache then
        local oldestNonce = nil
        local oldestTime = math.huge
        
        for n, t in pairs(Utils.Events.nonceCache) do
            if t < oldestTime then
                oldestTime = t
                oldestNonce = n
            end
        end
        
        if oldestNonce then
            Utils.Events.nonceCache[oldestNonce] = nil
            Utils.Events.nonceCacheSize = Utils.Events.nonceCacheSize - 1
        end
    end
    
    Utils.Events.nonceCache[nonce] = getCurrentTime()
    Utils.Events.nonceCacheSize = Utils.Events.nonceCacheSize + 1
    return true
end

-- * Validate timestamp and nonce (server-side only)
Utils.Functions.ValidateTimestampAndNonce = function(timestamp, nonce)
    if not IsDuplicityVersion() then
        return true
    end
    
    local currentTime = getCurrentTime()
    local timeDiff = math.abs(currentTime - timestamp)
    
    if timeDiff > 5 then
        return false, "Timestamp out of range (replay attack or clock skew)"
    end
    
    if Utils.Events.nonceCache[nonce] then
        return false, "Nonce already used (replay attack)"
    end
    
    addNonceToCache(nonce)
    
    return true
end

-- * serializing functions
local function escapeString(str)
    return str:gsub("\\", "\\\\"):gsub("|", "\\|"):gsub(":", "\\:")
end

local function unescapeString(str)
    return str:gsub("\\:", ":"):gsub("\\|", "|"):gsub("\\\\", "\\")
end

local function serializeTable(tbl, depth)
    if depth > 10 then return "{}" end
    
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
            val = "T" .. serializeTable(v, depth + 1)
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
                end
                
                if valType == "n" then
                    result[actualKey] = nil
                elseif valType == "d" then
                    result[actualKey] = tonumber(valData)
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
            end
            
            if valType == "n" then
                result[actualKey] = nil
            elseif valType == "d" then
                result[actualKey] = tonumber(valData)
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
            val = "T" .. serializeTable(v, 1)
        else
            return nil, "Unsupported type: " .. type(v)
        end
        
        parts[count] = key .. ":" .. val
    end
    
    local serializedData = table.concat(parts, "|")
    local timestamp = getCurrentTime()
    local nonce = generateNonce()
    
    -- Format: timestamp:nonce:serialized_data
    return timestamp .. ":" .. nonce .. ":" .. serializedData
end

Utils.Functions.DeserializeArgs = function(serialized)
    if not serialized or serialized == "" then
        return {}
    end
    
    -- Extract timestamp, nonce, and data
    local timestamp, nonce, data = serialized:match("^(%d+):(%w+):(.*)")
    
    if not timestamp or not nonce then
        Utils.Notify.Error("Invalid serialized format (missing timestamp or nonce)")
        return {}
    end
    
    timestamp = tonumber(timestamp)
    
    -- Validate timestamp and nonce (server-side only)
    if IsDuplicityVersion() then
        local valid, error = Utils.Functions.ValidateTimestampAndNonce(timestamp, nonce)
        if not valid then
            Utils.Notify.Error(error)
            return {}
        end
    end
    
    -- If no data after timestamp:nonce, return empty table
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
                end
                
                if valType == "n" then
                    result[actualKey] = nil
                elseif valType == "d" then
                    result[actualKey] = tonumber(valData)
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
            end
            
            if valType == "n" then
                result[actualKey] = nil
            elseif valType == "d" then
                result[actualKey] = tonumber(valData)
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
    end
    
    return result
end