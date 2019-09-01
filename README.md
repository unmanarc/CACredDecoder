# C-Ark Credential Decoder
A Tool for decoding C-ARK Credential files  
By Aaron Mizrachi <aaron@unmanarc.com>
v0.1 - Aug/2019 

## NOTE / POTENTIAL USAGE:
Acording to the vendor, this is not a vulnerability, this is a problem derivated by the misuse of the tools.

During a pentest, if someone is smart enough to reach the PSM and accidentally get access to the CredFile, someone can potentially use this file to establish a connection to the Vault and get the whole reign...

However, the credfile have some "restrictions" to avoid this file to be used in other environments (the hacker very own PSM). 

Sometimes, this restrictions are based on some self-included encryption key (when used without an HSM)... And when you reverse the raw key portion, it will show the first introduced key and/or the "random" generated plain key that it's changed everytime.

This the decrypted key portion can be used to re-create another file with another "security" parameters.

## Operation Mode

To generate the AES-256 (32 bytes) raw decryption key,  we take a pair of SHA1SUM from the "AdditionalInformation" credential field appending "0x00000000" and "0x00000001" for each Hash; the first Hash provides the first 20 bytes of the key, and the second one only the last 12 bytes. 

If there is any environmental restrictions (like IP/Host/exepath/...), we prepend each plaintext value to AdditionalInformation before taking both SHA1SUMs.

It's important to mention that the "ClientApp" field is transformed with  BASE64(SHA1SUM(strlower(ClientApp))) before being prepended to "AdditionalInformation" and generating both SHA1SUMs.

The decryption is done using AES-256-CBC OpenSSL function using the Password or NewPassword field. (https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)


We are using (verificationflags-16) for figuring which validation/restriction is in place:

    usingClientApp      = ((uVerificationsFlag&0x1) != 0);
    usingAppPath        = ((uVerificationsFlag&0x2) != 0);
    usingClientIP       = ((uVerificationsFlag&0x4) != 0);
    usingOSUser         = ((uVerificationsFlag&0x8) != 0);
    usingClientHostname = ((uVerificationsFlag&0x20) != 0);

and in the case that some restrictions are not displayed in the output credential file, you can always introduce them by hand. I think that we can both agree in that neither "app path" nor "client IP” is a truly random value.


## Items of concern we’d like to share:

- There is a OpenSSL function to derive text to AES-256 Key which is cryptographically strong, and some other better alternatives. We believe no one would actually recommend using a couple of SHA-1 to generate the key from a source with a low entropy model (this is not cryptographically strong).
- ClientIP/OSUser/AppPath/ClientHostname is taken only from the current computer running “createcredfile.exe", so it isn’t possible to produce the credential file outside the PSM/PVWA.
- Typing plaintext passwords manually into the PSM is not the best security practice, and if you want to use restrictions you are forced to, so the previous restriction will expose some keys to another attack vectors.
- The ClientIP is taken from only one interface, in some cases it will take dummy interfaces (ip: 169.254.x.x), reducing the entropy.


## Mitigation:

Use the HSM \o/


