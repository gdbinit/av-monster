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
 * macho.h
 *
 */

#include <mach-o/loader.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <stdint.h>
#include <string.h>
#include "structures.h"

// prototypes
uint8_t  process_header(vm_address_t address, struct header_info *headerInfo);
uint32_t find_strings(struct header_info *headerInfo,
                      const char *stringToSearch,
                      const uint32_t stringSize);
uint32_t find_install_scope(kmod_info_t *target_kmod, 
                            const uint32_t addressToSearch,
                            const struct header_info *headerInfo);
// hash.c
extern uint32_t FNV1A_Hash_Jesteress(const char *str, size_t wrdlen);

