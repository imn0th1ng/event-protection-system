-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!
-- ! Encrypt this file with FXAP or some lua obfuscators with. Otherwise it will cause security problems!

-- ? Başka bir scripti korumak için fxmanifest.lua içerisinde en yukarıya
-- ? shared_script 'wrapper.lua'
-- ? yapıştırmanız yeterlidir.

local isServer = IsDuplicityVersion()
local Config = {
    -- ? Buna büyük bir parantez açmak istiyorum, Eğer ki kütüphane ile kullanırsanız daha sağlıklı çalışacaktır. Fakat;
    -- ? Scriptler escrow ile şifrelenmişse veya değiştirmeye vaktiniz yok ise *bazı* örneğin market gibi scriptleri
    -- ? Bu ayar üzerinden eventleri otomatik kalibre edebilirsiniz. Büyük scriptlerde sorun yaratabilir.
    -- * __cfx'i exclude et
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