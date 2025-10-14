local public = {};


--
-- Encrypt strings
-- key - byte array with key
-- string - string to encrypt
-- modefunction - function for cipher mode to use
--
function public.encryptString(key, data, modeFunction)
    local iv = iv or {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    local keySched = aeslua.aes.expandEncryptionKey(key);
    local encryptedData = aeslua.buffer.new();
    
    for i = 1, #data/16 do
        local offset = (i-1)*16 + 1;
        local byteData = {string.byte(data,offset,offset +15)};
		
        modeFunction(keySched, byteData, iv);

        local unpackedString = '';
        for i=1,#byteData do
            unpackedString = unpackedString .. string.char(byteData[i]);
        end;

        aeslua.buffer.addString(encryptedData, unpackedString);    
    end
    
    return aeslua.buffer.toString(encryptedData);
end

--
-- the following 4 functions can be used as 
-- modefunction for encryptString
--

-- Electronic code book mode encrypt function
function public.encryptECB(keySched, byteData, iv) 
	aeslua.aes.encrypt(keySched, byteData, 1, byteData, 1);
end

-- Cipher block chaining mode encrypt function
function public.encryptCBC(keySched, byteData, iv) 
    aeslua.util.xorIV(byteData, iv);

    aeslua.aes.encrypt(keySched, byteData, 1, byteData, 1);    
        
    for j = 1,16 do
        iv[j] = byteData[j];
    end
end

-- Output feedback mode encrypt function
function public.encryptOFB(keySched, byteData, iv) 
    aeslua.aes.encrypt(keySched, iv, 1, iv, 1);
    aeslua.util.xorIV(byteData, iv);
end

-- Cipher feedback mode encrypt function
function public.encryptCFB(keySched, byteData, iv) 
    aeslua.aes.encrypt(keySched, iv, 1, iv, 1);    
    aeslua.util.xorIV(byteData, iv);
       
    for j = 1,16 do
        iv[j] = byteData[j];
    end        
end

--
-- Decrypt strings
-- key - byte array with key
-- string - string to decrypt
-- modefunction - function for cipher mode to use
--
function public.decryptString(key, data, modeFunction)
    local iv = iv or {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    
    local keySched;
    if (modeFunction == public.decryptOFB or modeFunction == public.decryptCFB) then
    	keySched = aeslua.aes.expandEncryptionKey(key);
   	else
   		keySched = aeslua.aes.expandDecryptionKey(key);
    end
    
    local decryptedData = aeslua.buffer.new();

    for i = 1, #data/16 do
        local offset = (i-1)*16 + 1;
        local byteData = {string.byte(data,offset,offset +15)};

		iv = modeFunction(keySched, byteData, iv);

        local unpackedString = '';
        for i=1,#byteData do
            unpackedString = unpackedString .. string.char(byteData[i]);
        end;

        aeslua.buffer.addString(decryptedData, unpackedString);
    end

    return aeslua.buffer.toString(decryptedData);    
end

--
-- the following 4 functions can be used as 
-- modefunction for decryptString
--

-- Electronic code book mode decrypt function
function public.decryptECB(keySched, byteData, iv) 

    aeslua.aes.decrypt(keySched, byteData, 1, byteData, 1);
    
    return iv;
end

-- Cipher block chaining mode decrypt function
function public.decryptCBC(keySched, byteData, iv) 
	local nextIV = {};
    for j = 1,16 do
        nextIV[j] = byteData[j];
    end
        
    aeslua.aes.decrypt(keySched, byteData, 1, byteData, 1);    
    aeslua.util.xorIV(byteData, iv);

	return nextIV;
end

-- Output feedback mode decrypt function
function public.decryptOFB(keySched, byteData, iv) 
    aeslua.aes.encrypt(keySched, iv, 1, iv, 1);
    aeslua.util.xorIV(byteData, iv);
    
    return iv;
end

-- Cipher feedback mode decrypt function
function public.decryptCFB(keySched, byteData, iv) 
    local nextIV = {};
    for j = 1,16 do
        nextIV[j] = byteData[j];
    end

    aeslua.aes.encrypt(keySched, iv, 1, iv, 1);
        
    aeslua.util.xorIV(byteData, iv);
    
    return nextIV;
end

aeslua.ciphermode = public;

return public;