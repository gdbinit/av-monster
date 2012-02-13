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
 * av-monster.h
 *
 */

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/kmod.h>
#include <i386/proc_reg.h>
#include <mach-o/loader.h>
#include "structures.h"

// prototypes
kmod_info_t* find_av_module(kmod_info_t *ki);

// registers.c
extern void disable_interrupts(void);
extern void enable_interrupts(void);
extern uint8_t disable_writeprotection (void);
extern uint8_t enable_writeprotection (void);
extern uint8_t verify_writeprotection (void);
// hash.c
extern uint32_t FNV1A_Hash_Jesteress(const char *str, size_t wrdlen);
// macho.c
extern uint8_t  process_header(vm_address_t targetAddress, struct header_info *headerInfo);
extern uint32_t find_strings(struct header_info *headerInfo,
                             const char *stringToSearch, 
                             const uint32_t stringSize);
extern uint32_t find_install_scope(kmod_info_t *target_kmod, 
                                   const uint32_t addressToSearch, 
                                   const struct header_info *headerInfo);


