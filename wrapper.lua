-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!

-- ? To protect another script, simply paste the following at the top of fxmanifest.lua:
-- ? shared_script ‘wrapper.lua’

local isServer = IsDuplicityVersion()
local Config = {
    -- ? I want to make a big point here: it will work better if you use it with the library. However;
    -- ? If the scripts are encrypted with escrow or you don't have time to change them, *some* scripts, such as market scripts,
    -- ? You can automatically calibrate events through this setting. It may cause problems in large scripts.
    -- * TODO: Exclude __cfx
    OverrideNatives = true,
}

Event = {} -- ! RANDOMIZE THE EVENT TABLE NAME

if (isServer) then
    Event.Server = {}
    
    Event.Server.RegisterServerEvent = function(name, handler)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        
        RegisterServerEvent(evName, function(encryptedData)
            local data = exports["event-protection-system"]:decryptMessage(encryptedData)
            handler(data)
        end)
    end

    -- ! Server to Client (might be throw error if source not available)
    Event.Server.TriggerClientEvent = function(name, source, ...)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        local data = exports["event-protection-system"]:encryptMessage(...)

        TriggerClientEvent(evName, source, data)
    end

    -- ! Server to Server
    Event.Server.TriggerEvent = function(name, ...)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        local data = exports["event-protection-system"]:encryptMessage(...)

        TriggerEvent(evName, data)
    end

    -- ! Client and Server to Server
    Event.Server.RegisterNetEvent = function(name, handler)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        
        RegisterNetEvent(evName, function(encryptedData)
            local data = exports["event-protection-system"]:decryptMessage(encryptedData)
            handler(data)
        end)
    end

    if (Config.OverrideNatives) then
        RegisterNetEvent = Event.Server.RegisterNetEvent
        TriggerEvent = Event.Server.TriggerEvent
        TriggerClientEvent = Event.Server.TriggerClientEvent
        RegisterServerEvent = Event.Server.RegisterServerEvent
    end
else
    Event.Client = {}

    Event.Client.TriggerServerEvent = function(name, ...)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        local data = exports["event-protection-system"]:encryptMessage(...)

        TriggerServerEvent(evName, data)
    end

    -- ! Client to Client
    Event.Client.TriggerEvent = function(name, ...)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        local data = exports["event-protection-system"]:encryptMessage(...)

        TriggerEvent(evName, data)
    end

    -- ! Server and Client to Client
    Event.Client.RegisterNetEvent = function(name, handler)
        local evName = exports["event-protection-system"]:CreateEventName(name)
        RegisterNetEvent(evName, function(encryptedData)
            local data = exports["event-protection-system"]:decryptMessage(encryptedData)
            handler(data)
        end)
    end

    if (Config.OverrideNatives) then
        RegisterNetEvent = Event.Client.RegisterNetEvent
        TriggerEvent = Event.Client.TriggerEvent
        TriggerServerEvent = Event.Client.TriggerServerEvent
    end
    

end
