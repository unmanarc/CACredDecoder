#include "aeskey_decoder.h"

#include <openssl/sha.h>
#include <openssl/bio.h>

#include <string>

#include <string.h>

using namespace std;


void decodeAESKey(sCrackingOptions *crackingOptions)
{

    list<string> clientApps;

    if (crackingOptions->usingClientApp)
    {
        if (!crackingOptions->sClientApp.empty())
            clientApps.push_back(crackingOptions->sClientApp);
        else
        {
            fprintf(stderr,"ERROR: value not provided \"ClientApp\" field... may fail\n");
            clientApps.push_back("");
        }
    }
    else
    {
        clientApps.push_back("");
    }

    for (const std::string & sClientApp : clientApps)
    {
        string keyPayload = crackingOptions->composeKeyPayload(sClientApp);
        sAesKey aesKey;

        if (keyPayload.size()<40)
        {
            fprintf(stderr, "WARNING: AdditionalInformation field may be corrupted (bytes=%lu, required=40), continuing...\n", keyPayload.size());
        }
        memset(aesKey.aeskey,0,AES_KEY_SIZE);
        uint8_t hash[SHA_DIGEST_LENGTH], hash2[SHA_DIGEST_LENGTH];
        SHA_CTX ctx, ctx2;
        SHA1_Init(&ctx);
        SHA1_Init(&ctx2);

        // Hash each piece of data as it comes in:
        SHA1_Update(&ctx, keyPayload.c_str(), strlen(keyPayload.c_str()));
        SHA1_Update(&ctx, "\0\0\0\0", 4);
        SHA1_Final(hash, &ctx);

        SHA1_Update(&ctx2, keyPayload.c_str(), strlen(keyPayload.c_str()));
        SHA1_Update(&ctx2, "\0\0\0\1", 4);
        SHA1_Final(hash2, &ctx2);

        // Composing key:
        memcpy(aesKey.aeskey,hash, SHA_DIGEST_LENGTH);
        memcpy(aesKey.aeskey+SHA_DIGEST_LENGTH,hash2, AES_KEY_SIZE-SHA_DIGEST_LENGTH);

        aesKey.sClientApp = sClientApp;

        crackingOptions->aesKeys.push_back(aesKey);
    }
}

