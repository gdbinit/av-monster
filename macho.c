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
 * macho.c
 *
 */

#include "macho.h"

/* 
 * process target kernel module header and retrieve some info we need
 */
uint8_t
process_header(vm_address_t targetAddress, struct header_info *headerInfo)
{
    // verify if it's a valid mach-o binary
    uint8_t *address    = NULL;
    uint32_t nrLoadCmds = 0;
    
    uint32_t magic = *(uint32_t*)(targetAddress);
    if (magic == MH_MAGIC)
	{
        struct mach_header *machHeader = (struct mach_header*)(targetAddress);
        nrLoadCmds = machHeader->ncmds;        
        // first load cmd address
        address = (uint8_t*)(targetAddress + sizeof(struct mach_header));
	}
    // error
    else
    {
        return(1);
    }
    
    // find the last command offset
    struct load_command *loadCommand = NULL;
    uint32_t i = 0;
    for (; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        switch (loadCommand->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)(loadCommand);
                struct section *section = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));

                uint32_t x = 0;
                for (; x < segmentCommand->nsects; x++)
                {
                    if (strncmp(section->segname, "__TEXT", 16) == 0)
                    {                        
                        if (strncmp(section->sectname, "__cstring", 16) == 0)
                        {
#if DEBUG
                            printf("[DEBUG] Found cstring section addr:0x%08x size:0x%08x!\n", section->addr, section->size);
#endif
                            headerInfo->cstringDataAddress  = section->addr;
                            headerInfo->cstringDataSize     = section->size;
                        }
                        else if (strncmp(section->sectname, "__text", 16) == 0)
                        {
                            headerInfo->textAddress = section->addr;
                            headerInfo->textSize    = section->size;
#if DEBUG
                            printf("[DEBUG] Found __text section addr:0x%08x size:0x%08x\n", headerInfo->textAddress, headerInfo->textSize);
#endif
                        }
                    }
                    section++;
                }                
            }
                // TODO :-)
            case LC_SEGMENT_64:
                break;
        }
        // advance to next command
        address += loadCommand->cmdsize;
    }
    return 0;
}

/*
 * find where in cstring section is the string we are looking for
 * we will use this address to find the caller of the string
 */
uint32_t 
find_strings(struct header_info *headerInfo, 
             const char *stringToSearch, 
             const uint32_t stringSize) // stringSize includes the NULL value
{
    uint8_t *tempAddress = (uint8_t*)(headerInfo->cstringDataAddress);
    uint8_t *cstringDataLimit = (uint8_t*)((uint32_t)tempAddress + headerInfo->cstringDataSize);
    
    uint32_t hashToMatch = FNV1A_Hash_Jesteress(stringToSearch, stringSize);
    
    char searchBuffer[stringSize];
    uint32_t searchBufferHash = 0;
    
    for (; tempAddress < cstringDataLimit; tempAddress++)
    {
        // copy the bytes to buffer
        memcpy(searchBuffer, tempAddress, stringSize);
        // generate the hash of the current bytes
        searchBufferHash = FNV1A_Hash_Jesteress(searchBuffer, stringSize);
        if (searchBufferHash == hashToMatch)
        {
#if DEBUG
            printf("[DEBUG] Found string address at 0x%08x (%s)\n", tempAddress, (char*)tempAddress);
#endif
            return((uint32_t)tempAddress);
        }
    }
    return(1);
}

/*
 * find where the kauth callback is being installed
 * we use the string address retrieved from above
 * we are looking for the parameter being pushed to esp+4
 * usually it follows this format, except for ESET
 * __text:00000E31 C7 44 24 08 00 00+   mov     dword ptr [esp+8], 0
 * __text:00000E39 C7 44 24 04 6C 13+   mov     dword ptr [esp+4], offset __Z14vnode_listenerP5ucredPvimmmm 
 * __text:00000E41 C7 04 24 60 2C 00+   mov     dword ptr [esp], offset aCom_apple_kaut ; "com.apple.kauth.vnode"
 * __text:00000E48 E8 4B 28 00 00       call    near ptr _kauth_listen_scope
 */
uint32_t 
find_install_scope(kmod_info_t *target_kmod, 
                   const uint32_t addressToSearch, 
                   const struct header_info *headerInfo)
{
    // NOTE: assumption that __text is located 0x1000 bytes after the module address
    // found at kmod_info_t
    uint8_t *address = (uint8_t*)(target_kmod->address+0x1000);
    uint8_t *limit = (uint8_t*)((uint32_t)target_kmod->address + 0x1000 + headerInfo->textSize);
    
    for (; address < limit; address++)
    {
        if (*(uint32_t*)address == addressToSearch)
        {
            /*
             * eset sets things differently...bahhh!!!
             * __text:00000D32 C7 44 24 08 00 00+  mov     dword ptr [esp+8], 0
             * __text:00000D3A C7 44 24 04 F0 4E+  mov     dword ptr [esp+4], offset _VnodeScopeListener
             */
            if (strcmp(target_kmod->name, "com.eset.kext.esets_kac") == 0)
            {
                // we don't need to search all remaining memory
                uint8_t *tempLimit = address+0x100;
                for (; address < tempLimit; address++)
                {
                    // match the first 4 bytes of each line
                    if ((*(uint32_t*)address == 0x082444c7) && (*(uint32_t*)(address+8) == 0x042444c7))
                    {
#if DEBUG
                        printf("[DEBUG] Found ESET function address at 0x%08x 0x%08x\n", address+8, *(uint32_t*)(address+8+4));
#endif
                        return(*(uint32_t*)(address+8+4));
                    }
                }
            }
            // everyone else follows the same format ;-)
            else
            {
#if DEBUG
                printf("[DEBUG] Found function address at 0x%08x 0x%08x 0x%08x\n", address, address-7, *(uint32_t*)(address-7));
#endif
                return(*(uint32_t*)(address-7));
            }
        }
    }
    return(1);
}
