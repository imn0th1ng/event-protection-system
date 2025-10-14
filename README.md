# First of all
First, to explain why I did this project, it is an event protection function that I developed for testing purposes in the early development version of my own anti-cheat, due to the popularity of mostly illegal (not within CitizenFX) anti-cheats and their ineffectiveness in terms of events. If possible, I encourage those who know Lua and are interested in developing it to contact me so we can work on this project together. I have no personal gain in mind for this project because I love this platform and want to see it grow. As far as I can see, everything is now sold for money in FiveM, which I think is wrong. Of course, making money is very important, otherwise there would be no motivation for people, but in this period where cheats can no longer be prevented and have proliferated, these cheats can harm both the player experience and server owners. I don't want to prolong this or make it personal. If you want to improve things and have an idea in mind, please get in touch with me, and let's work together to make this platform even better.

# Possible vulnerabilities
One of the biggest problems with this project is the possibility that protection functions can be called by cheats. To counter this, you can use certain Lua libraries to analyze where and how the function is called, and if someone enters a specific file, i.e., the runtime, you can detect this and ban them. The primary reason I'm sharing this as open source is that most anti-cheat protections (I can't name them) have become monopolized, resulting in them no longer being updated, allowing cheats to easily bypass them. I'm considering developing an anti-cheat system in the future. This is actually a source that came to mind during the initial development stages of the event protection system and provides excellent protection (more than sufficient for skid cheaters). Also if your player has a different time on client (like a different time zone) probably player will gets a false ban. For solving that we can get a spesific timezone in lua but i will do that with updates when i have time.

# Advantages of this system
The advantage of this system is that the name is regenerated differently for each event using HMAC/SHA256 without requiring any action on your part, and the payload (i.e., your event content) is fully encrypted using AES128 CBC, preventing event loggers from reading it directly. Of course, this will come at a CPU cost, but I recommend using it only when you are giving items and money. If you use it for unnecessary events, the CPU cost will increase significantly.

# FAQ
Q: Is this an anti-cheat?

A: Both yes and no. It's not a fully integrated anti-cheat system; you may need to configure certain events and fine-tune them yourself.

Q: Does it provide 100% security?

A: Of course not. However, as far as I can tell, people who use cheats nowadays search for event exploits through menus and by dumping resources, so it is a resource that can prevent them from obtaining many valuable items on the server, such as items and money.

Q: How does it works?

A: To put it simply, the logic is extremely straightforward. On the server side: RegisterServerEvent, TriggerClientEvent. On the client side: RegisterNetEvent, TriggerEvent, TriggerServerEvent. This involves encrypting client-server & server-client & client-client requests, applying a timestamp and nonce (for replay attacks on events just in case), and verifying them on the server to execute the event.

Q: Can someone bypass this method?

A: If you place resources in escrow (or obfuscate them illegally, which I do not recommend as it reduces performance and may require some adjustments), the likelihood of bypassing them is very low. It would need to extract the AES key via memory analysis, use the function that decrypts it in the Lua executor to deobfuscate it, enter the timestamp, and send the event that way. In a scenario where the AES key hasn't been leaked and you've changed the protection's table name and escrowed your resources, bypassing this type of security would take a very, very long time.

Q: Is there will be a performance cost?

A: Yes unfortunately. That is because of lua is a slow language for mathematical operations.

Q: Did you used AI? (its totally not a faq but i just want to explain myself)

A: Yes but not for main logic. AI just wrote the serializing and deserializing functions.

If you have any questions to me you can ask from discord or you can pm me on cfx.re forum.

# WARNINGS!!
There is one config file at the top level on both the client and server. You must enter a random AES and SHA key. Otherwise, security vulnerabilities may arise. To be on the safe side, definitely randomize table names such as Utils and Events. Otherwise, a Lua executor capable of thread injection could gain access to all functions. Finally, after doing all of this, fully encrypt the system using the escrow system!

The whole system is not tested on public servers so if you want to tell me smth about any error or improvement just text me on cfx discord or smth 

# Supported variable types
String
Integer
Boolean
Table
Nil

# Usage
* CALL MAIN OBJECT
- You can call the event object with this export
local Event = exports["event-protection-system"]:getEventSystem()

# FUNCTIONS
* Client
* Event.Client.RegisterNetEvent(name, handler)
* Event.Client.TriggerEvent(name, args)
* Event.Client.TriggerServerEvent(name, args)
* Server
* Event.Server.RegisterServerEvent(name, handler)
* Event.Server.RegisterNetEvent(name, handler)
* Event.Server.TriggerClientEvent(name, args)
* Event.Server.TriggerEvent(name, args)

# Features
* AES128 encryption (enough for fivem tho)
* HMAC/SHA256 hashing on event names
* Timestamp checking (there is a tolerance. i set it to 5secs)
* Anti replay attacks (its basically checking the nonce)
* 4 different encryption modes. default is set to CBCMode which is most secure option atm. (aeslua.lua.ECBMODE, aeslua.lua.CBCMODE, aeslua.lua.OFBMODE, aeslua.lua.CFBMODE)
* 3 different key options. If you want to change encryption key length you should also change config. default is set to AES128 (aeslua.AES128, aeslua.AES192, aeslua.AES256)

# Want to help me?
You can send me a message on Discord (my username is nothingthefinest). That way, if you have any requests, I can add them, or you can help me write the code. Alternatively, you can also help me fix any potential bugs by sending an update request via GitHub. And if you help me with the development, I would really appreciate it.

# Want to support me?
Basically just drop a star nothing else

# Credits
I have a special thanks for to who makes the crypto libraries in pure lua. If they aren't exist, i wasnt able to do the whole project today.

* https://github.com/Egor-Skriptunoff/pure_lua_SHA
* https://github.com/bighil/aeslua





