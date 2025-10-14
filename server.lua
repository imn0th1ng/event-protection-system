Config = {
    SHAKey = "4b7e9f2a5d8c1e6b3a9f5d2c7e1b4a8d6c3f9e2b5a8d1c4e7b3a6f9d2e5c8b1a4", -- ! CHANGE ME!
    AESKey = "7f3a9d2e5b8c1f4a6e9d2c5b8f1a4e7d" -- ! CHANGE ME!
}

---------------------------------------------------------------------------------------------------------------------------------------

Event = {} -- ! CHANGE ME!
Event.Server = {}
Event.Functions = {}

-- TODO do the addeventhandler somehow

-- ! Client to Server
Event.Server.RegisterServerEvent = function(name, cb)
    local evName = Utils.Events.CreateEventName(name)
    RegisterServerEvent(evName, function(encryptedData)
        local decryptedData = aeslua.lua.decrypt(Config.AESKey, encryptedData, aeslua.lua.AES128, aeslua.lua.CBCMODE)
        local deSerialized = Utils.Functions.DeserializeArgs(decryptedData)
        local rawData = table.unpack(deSerialized)
        cb(rawData)
    end)
end

-- ! Server to Client
Event.Server.TriggerClientEvent = function(name, source, ...)
    local evName = Utils.Events.CreateEventName(name)
    local args = table.pack(...)
    local serializedArgs = Utils.Functions.SerializeArgs(args)
    local encryptedData = aeslua.lua.encrypt(Config.AESKey, serializedArgs, aeslua.lua.AES128, aeslua.lua.CBCMODE)

    TriggerClientEvent(evName, source, encryptedData)
end

-- ! Server to Server
Event.Server.TriggerEvent = function(name, ...)
    local evName = Utils.Events.CreateEventName(name)
    local args = table.pack(...)
    local serializedArgs = Utils.Functions.SerializeArgs(args)
    local encryptedData = aeslua.lua.encrypt(Config.AESKey, serializedArgs, aeslua.lua.AES128, aeslua.lua.CBCMODE)

    TriggerEvent(evName, encryptedData)
end

-- ! Client&Server to Server
Event.Server.RegisterNetEvent = function(name, cb)
    local evName = Utils.Events.CreateEventName(name)
    RegisterNetEvent(evName, function(encryptedData)
        local decryptedData = aeslua.lua.decrypt(Config.AESKey, encryptedData, aeslua.lua.AES128, aeslua.lua.CBCMODE)
        local deSerialized = Utils.Functions.DeserializeArgs(decryptedData)
        local rawData = table.unpack(deSerialized)
        cb(rawData)
    end)
end


exports("getEventSystem", function()
    return Event
end)