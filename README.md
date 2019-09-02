# C-Ark Credential Decoder
A Tool for decoding C-ARK Credential files  
By Aaron Mizrachi <aaron@unmanarc.com>
v1.0a - Sep/2019 

## NOTE / POTENTIAL USAGE:

**Acording to the vendor, this is not a vulnerability, this is a problem derivated from the misuse of the tool.**

During a pentest, if someone is smart enough to reach the PSM and accidentally get access to the CredFile, someone can potentially use this file to establish a connection to the Vault and get the whole reign...

To have a countermeasure, most Credentials Files place some "restrictions" to avoid the password to be used in a different environment/computer (Eg. the hacker very own PSM). 

However, those restrictions can be modified *if you reverse and get the raw key portion*. This  decrypted key portion can be used to re-create another file with another "security" parameters (Eg. another host, another application, another OS User).

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



## Mitigation:

Use the HSM \o/, don't store the decryption key in the cred file.
