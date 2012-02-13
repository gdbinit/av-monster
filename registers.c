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
 * registers.c
 *
 */

#include "registers.h"

// enable and disable interrupts
void enable_interrupts(void)
{
    __asm__ volatile("sti");
}

void disable_interrupts(void)
{
    __asm__ volatile("cli");
}

/*
 * disable the CR0 write protection 
 * so we can write to kernel memory
 * return values: 0 sucess, 1 failure
 */
uint8_t
disable_writeprotection (void)
{
#if DEBUG
    printf("[DEBUG] Disabling CR0 write protect\n");
#endif
	uintptr_t cr0 = 0;
	// retrieve current value
	cr0 = get_cr0();
	// remove the WP bit
	cr0 = cr0 & ~CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) == 0)
        return(0);
    else
        return(1);
}

/*
 * enable the Write Protection bit in CR0 register
 * return values: 0 sucess, 1 failure
 */
uint8_t
enable_writeprotection (void)
{
#if DEBUG
    printf("[DEBUG] Enabling CR0 write protect\n");
#endif
	uintptr_t cr0 = 0;
	// retrieve current value
	cr0 = get_cr0();
	// add the WP bit
	cr0 = cr0 | CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) != 0)
        return(0);
    else
        return(1);
}

/*
 * check if CR0 WP is set or not
 * 0 - it's set
 * 1 - not set
 */
uint8_t 
verify_writeprotection (void)
{
#if DEBUG
    printf("[DEBUG] Verifying current CR0 write protect\n");
#endif
    uintptr_t cr0 = 0;
    cr0 = get_cr0();
    if (cr0 & CR0_WP)
        return(0);
    else
        return(1);
}
