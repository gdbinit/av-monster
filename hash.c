/*
 *
 *  _______         __    __          ___ ___  __                     
 * |   _   |.-----.|  |_ |__| ______ |   Y   ||__|.----..--.--..-----.
 * |.  1   ||     ||   _||  ||______||.  |   ||  ||   _||  |  ||__ --|
 * |.  _   ||__|__||____||__|        |.  |   ||__||__|  |_____||_____|
 * |:  |   |                         |:  1   |                        
 * |::.|:. |                          \:.. ./                         
 * `--- ---'                           `---'                          
 * 
 *  ___ ___                       __                
 * |   Y   |.-----..-----..-----.|  |_ .-----..----.
 * |.      ||  _  ||     ||__ --||   _||  -__||   _|
 * |. \_/  ||_____||__|__||_____||____||_____||__|  
 * |:  |   |                                        
 * |::.|:. |                                        
 * `--- ---' 
 *
 * (c) 2011,2012, fG! <reverser@put.as> http://reverse.put.as
 * 
 * hash.c
 *
 */

#include "hash.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// http://encode.ru/threads/1160-Fastest-non-secure-hash-function

uint32_t FNV1A_Hash_Jesteress(const char *str, size_t wrdlen)
{
    const uint32_t PRIME = 709607;
    uint32_t hash32 = 2166136261;
    const char *p = str;
    
    // Idea comes from Igor Pavlov's 7zCRC, thanks.
    /*
     for(; wrdlen && ((unsigned)(ptrdiff_t)p&3); wrdlen -= 1, p++) {
     hash32 = (hash32 ^ *p) * PRIME;
     }
     */
    for(; wrdlen >= 2*sizeof(DWORD); wrdlen -= 2*sizeof(DWORD), p += 2*sizeof(DWORD)) {
        hash32 = (hash32 ^ (ROL(*(DWORD *)p,5)^*(DWORD *)(p+4))) * PRIME;        
    }
    // Cases: 0,1,2,3,4,5,6,7
    if (wrdlen & sizeof(DWORD)) {
        hash32 = (hash32 ^ *(DWORD*)p) * PRIME;
        p += sizeof(DWORD);
    }
    if (wrdlen & sizeof(WORD)) {
        hash32 = (hash32 ^ *(WORD*)p) * PRIME;
        p += sizeof(WORD);
    }
    if (wrdlen & 1) 
        hash32 = (hash32 ^ *p) * PRIME;
    
    return hash32 ^ (hash32 >> 16);
}

// http://encode.ru/threads/612-Fastest-decompressor!?p=22184&viewfull=1#post22184
UINT FNV1A_Hash_WHIZ(const char *str, size_t wrdlen)
{
    const UINT PRIME = 1607;
    
    UINT hash32 = 2166136261;
    const char *p = str;
    
    for(; wrdlen >= sizeof(DWORD); wrdlen -= sizeof(DWORD), p += sizeof(DWORD)) {
        hash32 = (hash32 ^ *(DWORD *)p) * PRIME;
    }
    if (wrdlen & sizeof(WORD)) {
        hash32 = (hash32 ^ *(WORD*)p) * PRIME;
        p += sizeof(WORD);
    }
    if (wrdlen & 1) 
        hash32 = (hash32 ^ *p) * PRIME;
    
    return hash32 ^ (hash32 >> 16);
}
