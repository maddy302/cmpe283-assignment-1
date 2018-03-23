/*  
 *  cmpe283-1.c - Kernel module for CMPE283 assignment 1
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <asm/msr.h>

#define MAX_MSG 80

/*
 * Model specific registers (MSRs) by the module.
 * See SDM volume 4, section 2.1
 */

#define IA32_VMX_BASIC 			0x00000480
#define IA32_VMX_TRUE_PINBASED_CTLS	0x0000048D
#define IA32_VMX_TRUE_PROCBASED_CTLS	0x0000048E
#define IA32_VMX_PROCBASED_CTLS2	0x0000048B
#define IA32_VMX_TRUE_EXIT_CTLS    	0x0000048F
#define IA32_VMX_TRUE_ENTRY_CTLS	0x00000490

#define BIT55 23
#define BIT63 31


/*
 * struct caapability_info
 *
 * Represents a single capability (bit number and description).
 * Used by report_capability to output VMX capabilities.
 */
struct capability_info {
	uint8_t bit;
	const char *name;
};


/*
 * Pinbased capabilities
 * See SDM volume 3, section 24.6.1
 */
struct capability_info pinbased[5] =
{
	{ 0, "EXTERNAL INTERRUPT EXITING" },
	{ 3, "NMI EXITING" },
	{ 5, "VIRTUAL NMIs" },
	{ 6, "ACTIVATE VMX PREEMPTION TIMER" },
	{ 7, "PROCESS POSTED INTERRUPTS" }
};

/*
 * Processor based Control capabilities
 */
struct capability_info procbased[21] =
{
    { 2, "INTERRUPT-WINDOW EXITING" },
    { 3, "USE TSC OFFSETTING" },
    { 7, "HLT EXITING" },
    { 9, "INVLPG EXITING" },
    { 10, "MWAIT EXITING" },
    { 11, "RDPMC EXITING" },
    { 12, "RDTSC EXITING" },
    { 15, "CR3-LOAD EXITING" },
    { 16, "CR3-STORE EXITING" },
    { 19, "CR8-LOAD EXITING" },
    { 20, "CR8-STORE EXITING" },
    { 21, "USE TPR SHADOW" },
    { 22, "NMI-WINDOW EXITING" },
    { 23, "MOV-DR EXITING" },
    { 24, "UNCONDITIONAL I/O EXITING" },
    { 25, "USE I/O BITMAPS" },
    { 27, "MONITOR TRAP FLAG" },
    { 28, "USE MSR BITMAPS" },
    { 29, "MONITOR EXITING" },
    { 30, "PAUSE EXITING" },
    { 31, "ACTIVATE SECONDARY CONTROLS" }
};


/*
 * Secondary Processor based Control capabilities
 */
struct capability_info secprocbased[23] =
{
    { 0, "VIRTUALIZE APIC ACCESSES" },
    { 1, "ENABLE EPT" },
    { 2, "DESCRIPTOR-TABLE EXITING" },
    { 3, "ENABLE RDTSCP" },
    { 4, "VIRTUALIZE x2APIC MODE" },
    { 5, "ENABLE VPID" },
    { 6, "WBINVD EXITING" },
    { 7, "UNRESTRICTED GUEST" },
    { 8, "APIC-REGISTER VIRTUALIZATION" },
    { 9, "VIRTUAL-INTERRUPT DELIVERY" },
    { 10, "PAUSE-LOOP EXITING" },
    { 11, "RDRAND EXITING" },
    { 12, "ENABLE INVPCID" },
    { 13, "ENABLE VM FUNCTIONS" },
    { 14, "VMCS SHADOWING" },
    { 15, "ENABLE ENCLS EXITING" },
    { 16, "RDSEED EXITING" },
    { 17, "ENABLE PML" },
    { 18, "EPT-VIOLATION #VE" },
    { 19, "CONCEAL VMX FROM PT" },
    { 20, "ENABLE XSAVES/XRSTORS" },
    { 22, "MODE-BASED EXECUTE CONTROL FOR EPT" },
    { 25, "USE TSC SCALING" }
};

/*
 * Exit Control capabilities
 */
struct capability_info exitcntrls[11] =
{
    { 2, "SAVE DEBUG CONTROLS" },
    { 9, "HOST ADDRESS-SPACE SIZE" },
    { 12, "LAOD IA32_PERF_GLOBAL_CTRL" },
    { 15, "ACKNOWLEDGE INTERRUPT ON EXIT" },
    { 18, "SAVE IA32_PAT" },
    { 19, "LOAD IA32_PAT" },
    { 20, "SAVE IA32_EFER" },
    { 21, "LOAD IA32_EFER" },
    { 22, "SAVE VMX-PREEMPTION TIMER VALUE" },
    { 23, "CLEAR IA32_BNDCFGS" },
    { 24, "CONCEAL VM EXITS FROM INTEL PT" }
};

/*
 * Entry Control capabilities
 */
struct capability_info entry[9] =
{
	{ 2, "LOAD DEBUG CONTROLS" },
	{ 9, "IA-32e MODE GUEST" },
	{ 10, "ENTRY TO SMM" },
	{ 11, "DEACTIVATE DUAL-MONITOR TREATMENT" },
	{ 13, "LOAD IA32_PERF_GLOBAL_CTRL" },
	{ 14, "LOAD IA32_PAT" },
	{ 15, "LOAD IA32_EFER" },
	{ 16, "LOAD IA32_BNDCFGS" },
	{ 17, "CONCEAL VM ENTRIES FROM INTEL PT" }
};

/*
 * read_msr
 *
 * Checks if the bit 55 of IA32_VMX_BASIC and Bit63 of IA32_VMX_PROCBASED_CLTS is set or not
 */

static void read_msr(void)
{
    unsigned int high, low;

	// Bit 55 of IA32_VMX_BASIC
    rdmsr(IA32_VMX_BASIC, low, high);

    if(test_bit(BIT55, (unsigned long*)&high))
        printk("Bit 55 of IA32_VMX_BASIC is set!\n");
    else
        printk("Bit 55 of IA32_VMX_BASIC is not set!\n");


	//Bit 63 of IA32_VMX_PROCBASED_CLTS
    rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS, low, high);

    if(test_bit(BIT63, (unsigned long*)&high))
        printk("Bit 63 of IA32_VMX_PROCBASED_CLTS is set!\n");
    else
        printk("Bit 63 of IA32_VMX_PROCBASED_CLTS is not set!\n");
    
}


/*
 * report_capability
 *
 * Reports capabilities present in 'cap' using the corresponding MSR values
 * provided in 'lo' and 'hi'.
 *
 * Parameters:
 *  cap: capability_info structure for this feature
 *  len: number of entries in 'cap'
 *  lo: low 32 bits of capability MSR value describing this feature
 *  hi: high 32 bits of capability MSR value describing this feature
 */
void
report_capability(struct capability_info *cap, uint8_t len, uint32_t lo,
    uint32_t hi)
{
	uint8_t i;
	struct capability_info *c;
	char msg[MAX_MSG];

	memset(msg, 0, sizeof(msg));

	for (i = 0; i < len; i++) {
		c = &cap[i];
		snprintf(msg, 79, "  %s: Can set=%s, Can clear=%s\n",
		    c->name,
		    (hi & (1 << c->bit)) ? "Yes" : "No",
		    !(lo & (1 << c->bit)) ? "Yes" : "No");
		printk(msg);
	}
}

/*
 * detect_vmx_features
 *
 * Detects and prints VMX capabilities of this host's CPU.
 */
void
detect_vmx_features(void)
{
	uint32_t lo, hi;

	/* Check if BIT 55 of IA32_VMX_BASIC and BIT 63 of 			   IA32_VMX_TRUE_PROCBASED_CTLS is set or not  */

	read_msr();

	/* Pinbased controls */
	rdmsr(IA32_VMX_TRUE_PINBASED_CTLS, lo, hi);
	pr_info("True Pinbased Controls MSR: 0x%llx\n",
		(uint64_t)(lo | (uint64_t)hi << 32));
	report_capability(pinbased, 5, lo, hi);

	/* Primary Processor based controls */
	rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS, lo, hi);
	pr_info("True Processor based Controls MSR: 0x%llx\n",
		(uint64_t)(lo | (uint64_t)hi << 32));
	report_capability(procbased, 21, lo, hi);

	/* Secondary Processor based controls */
	rdmsr(IA32_VMX_PROCBASED_CTLS2, lo, hi);
	pr_info("Secondary Processor based Controls MSR: 0x%llx\n",
		(uint64_t)(lo | (uint64_t)hi << 32));
	report_capability(secprocbased, 23, lo, hi);

	/* Exit controls */
	rdmsr(IA32_VMX_TRUE_EXIT_CTLS, lo, hi);
	pr_info("True Exit Controls MSR: 0x%llx\n",
		(uint64_t)(lo | (uint64_t)hi << 32));
	report_capability(exitcntrls, 11, lo, hi);
    
    	/* Entry controls */
    	rdmsr(IA32_VMX_TRUE_ENTRY_CTLS, lo, hi);
    	pr_info("True Entry Controls MSR: 0x%llx\n",
            	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(entry, 9, lo, hi);
}

/*
 * init_module
 *
 * Module entry point
 *
 * Return Values:
 *  Always 0
 */
int
init_module(void)
{
	printk(KERN_INFO "CMPE 283 Assignment 1 Module Start\n");

	detect_vmx_features();

	/* 
	 * A non 0 return means init_module failed; module can't be loaded. 
	 */
	return 0;
}

/*
 * cleanup_module
 *
 * Function called on module unload
 */
void
cleanup_module(void)
{
	printk(KERN_INFO "CMPE 283 Assignment 1 Module Exits\n");
}
