#include "slab.h"
#include <math.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define BYTE (8)

typedef struct link {
    void* slab;
    int size_in_blocks;

    short L1_offset;

    int* free_spot;

    struct link* next_slab;
} slabs;

struct kmem_cache_s {

    const char* name;

    size_t obj_size;

    void(*constructor)(void*);
    void(*destructor)(void*);

    slabs* empty_slabs;
    slabs* mixed_slabs;
    slabs* full_slabs;

    char expanded;
    char err;

    short next_offset;
    short num_of_offsets;

    struct kmem_cache_s* next_cache;
};

void* mem_start;
int blocks;
int blocks_pow2;
char* buddy_start;
kmem_cache_t* first_cache;
kmem_cache_t* cache_spot_list;
slabs* slab_spot_list;
HANDLE mutex;
char * names;

void print_info(const char * msg) {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(console, 10);
    printf_s(msg);
    SetConsoleTextAttribute(console, 15);
}

void print_error(const char* msg) {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(console, 12);
    printf_s(msg);
    SetConsoleTextAttribute(console, 15);
}

void merge_buddies() {
    for (int i = 0; i < blocks_pow2; i++) {
        int iterations = pow(2, blocks_pow2 - i - 1);
        for (int j = 0, start_point = (int)pow(2, blocks_pow2 - i) - 1; j < iterations; j++, start_point += 2) {
            // Proveri bit prvog buddy bloka
            int byte_no1 = start_point / BYTE;
            int bit_no1 = start_point % BYTE;

            int shift1 = BYTE - bit_no1 - 1;
            int check1 = 1 << shift1;

            int test1 = *(buddy_start + byte_no1) & check1;

            // Proveri bit drugog buddy bloka
            int byte_no2 = (start_point + 1) / BYTE;
            int bit_no2 = (start_point + 1) % BYTE;

            int shift2 = BYTE - bit_no2 - 1;
            int check2 = 1 << shift2;

            int test2 = *(buddy_start + byte_no2) & check2;

            // Proveri i spoji 
            if (test1 && test2) {
                // Resetuj bitove na 0
                int kick1 = 255 - check1; // Sve jedinice osim 0 na mestu bit_no1
                int kick2 = 255 - check2; // Sve jedinice osim 0 na mestu bit_no2

                *(buddy_start + byte_no1) &= kick1;
                *(buddy_start + byte_no2) &= kick2;

                // Postavi bit pretka na 1
                int byte_no = (start_point / 2) / BYTE;
                int bit_no = (start_point / 2) % BYTE;

                int shift = BYTE - bit_no - 1;
                int add = 1 << shift;

                *(buddy_start + byte_no) |= add;
            }
        }
    }
}

void * buddy_alloc(unsigned size_in_blocks) {
    int power = (int)ceil(log(size_in_blocks) / log(2));

    int current_power = power;
    while (current_power <= blocks_pow2) {
        int start = (int)pow(2, blocks_pow2 - current_power) - 1;
        int end = (int)pow(2, blocks_pow2 - current_power + 1) - 1;

        int i;
        for (i = start; i < end; i++) {
            int byte_no = i / BYTE;
            int bit_no = i % BYTE;

            int shift = BYTE - bit_no - 1;
            int check = 1 << shift;

            if (*(buddy_start + byte_no) & check) {
                if (current_power == power) {
                    // Pronadjen najmanji dovoljno veliki blok
                    int kick = 255 - check;
                    *(buddy_start + byte_no) &= kick; // Oznaci da je blok zauzet postavljanjem odgovarajuceg bita na 0

                    void * address = (char*)mem_start + (i - start)*BLOCK_SIZE*(int)pow(2, power);
                    return address;
                }
                else {
                    // Podeli blok na dva manja i ponovo pokusaj da zauzmes manji blok
                    int kick = 255 - check; // Sve jedinice osim 0 na mestu bit_no

                    *(buddy_start + byte_no) &= kick; // Postavi bit na mestu bit_no na 0

                    // Postavi bit potomka 1 na 1
                    int byte_no1 = (2 * i + 1) / BYTE;
                    int bit_no1 = (2 * i + 1) % BYTE;

                    int shift1 = BYTE - bit_no1 - 1;
                    int add1 = 1 << shift1;

                    *(buddy_start + byte_no1) |= add1;

                    // Postavi bit potomka 2 na 1
                    int byte_no2 = (2 * i + 2) / BYTE;
                    int bit_no2 = (2 * i + 2) % BYTE;

                    int shift2 = BYTE - bit_no2 - 1;
                    int add2 = 1 << shift2;

                    *(buddy_start + byte_no2) |= add2;

                    current_power--;
                    break;
                }
            }
        }
        if (i == end) { // Ukoliko nije pronadjen ni jedan slobodan blok na ovom nivou pokusaj da pronadjes slobodan blok veceg nivoa
            current_power++;
        }
    }

    return NULL; // Nije moguce zauzeti memoriju jer ne postoji slobodan blok dovoljne velicine
}

void buddy_dealloc(void* address, int size_in_blocks) {
    int diff = (char*)address - mem_start;
    diff /= BLOCK_SIZE;

    int block_no = diff / size_in_blocks;
    int power = (int)ceil(log(size_in_blocks) / log(2));
    int start = (int)pow(2, blocks_pow2 - power) - 1 + block_no;

    int byte_no = start / BYTE;
    int bit_no = start % BYTE;

    int shift = BYTE - bit_no - 1;
    int add = 1 << shift;

    *(buddy_start + byte_no) |= add;

    // DOhvati informacije o buddy bloku
    int byte_noB;
    int bit_noB;

    if (start % 2) {
        byte_noB = (start + 1) / BYTE;
        bit_noB = (start + 1) % BYTE;

    }
    else {
        byte_noB = (start - 1) / BYTE;
        bit_noB = (start - 1) % BYTE;
    }
    int shiftB = BYTE - bit_noB - 1;
    int checkB = 1 << shiftB;

    if (*(buddy_start + byte_noB) & checkB) { // Buddy blok je slobodan
        merge_buddies();
    }
}

void kmem_init(void * space, int block_num)
{
    mutex = CreateMutex(NULL, FALSE, NULL);

    if (block_num < 4) {
        print_error("Premalo blokova da bi memorija radila!!!\n");
        exit(-1);
    }
    mem_start = space;
    blocks = block_num;

    blocks_pow2 = (int)ceil(log(blocks) / log(2));
    int next2 = (int)pow(2, blocks_pow2);

    buddy_start = (char*)space + BLOCK_SIZE * (blocks - ((2 * next2 / BYTE) + 1) / BLOCK_SIZE - 1);
    /*
    for (int i = 0; i < block_num*BLOCK_SIZE; i++) {
        *((char*)mem_start + i) = 0;
    }
    */
    // Inicijalizuj sve vrednosti blokova u buddy alokatoru na 0 
    for (int i = 0; i < 2 * next2 / BYTE; i++) {
        *(buddy_start + i) = 0;
    }

    // Postavi vrednosti pojedinacnih blokova na 1
    int start_point = next2 - 1; // Pocetak bitova za blokove velicine 1 ce biti 2^(blocks_pow2 - 0) (0, jer je 1 = 2^0) - 1 sto je jednako vrednosti next2 - 1

    for (int i = 0; i < blocks - ((2 * next2 / BYTE) + 1) / BLOCK_SIZE - 1; i++) {
        int byte_no = (start_point + i) / BYTE;
        int bit_no = (start_point + i) % BYTE;

        int shift = BYTE - bit_no - 1;
        int add = 1 << shift;

        *(buddy_start + byte_no) |= add;
    }

    // Spoj blokove
    merge_buddies();
    /* // Ispis stanja buddy alokatora
    for (int i = 0; i < 2 * next2 / BYTE; i++) {
        printf_s("Buddy alocator: %d\n", (int)*(buddy_start + i));
    }
    */

    if (2 * next2 / BYTE + 104 < BLOCK_SIZE) {
        names = buddy_start + 2 * next2 / BYTE;
    }
    else {
        names = buddy_alloc(1);
        if (names == NULL) {
            print_error("Nedovoljno memorije za nastavak rada.\n");
            exit(-2);
        }

    }

    sprintf_s(names, 7, "size_5");
    sprintf_s(names + 8, 7, "size_6");
    sprintf_s(names + 16, 7, "size_7");
    sprintf_s(names + 24, 7, "size_8");
    sprintf_s(names + 32, 7, "size_9");
    sprintf_s(names + 40, 8, "size_10");
    sprintf_s(names + 48, 8, "size_11");
    sprintf_s(names + 56, 8, "size_12");
    sprintf_s(names + 64, 8, "size_13");
    sprintf_s(names + 72, 8, "size_14");
    sprintf_s(names + 80, 8, "size_15");
    sprintf_s(names + 88, 8, "size_16");
    sprintf_s(names + 96, 8, "size_17");

    // Alociraj jedan blok za podatke o kesevima
    cache_spot_list = buddy_alloc(1);
    if (cache_spot_list == NULL) {
        print_error("Nedovoljno memorije za nastavak rada.\n");
        exit(-2);
    }

    int free_caches = BLOCK_SIZE / sizeof(kmem_cache_t);
    // Postavi pokazivace u listi na sledece prazno mesto
    for (int i = 0; i < free_caches - 1; i++) {
        (cache_spot_list + i)->next_cache = cache_spot_list + i + 1;
    }
    (cache_spot_list + free_caches - 1)->next_cache = NULL;

    first_cache = NULL;

    // Alociraj jedan blok za podatke o plocama
    slab_spot_list = buddy_alloc(1);
    if (slab_spot_list == NULL) {
        print_error("Nedovoljno memorije za nastavak rada.\n");
        exit(-2);
    }

    int free_slabs = BLOCK_SIZE / sizeof(slabs);

    // Postavi pokazivace u listi na sledece prazno mesto
    for (int i = 0; i < free_slabs - 1; i++) {
        (slab_spot_list + i)->next_slab = slab_spot_list + (i + 1);
    }
    (slab_spot_list + free_slabs - 1)->next_slab = NULL;
}

kmem_cache_t * kmem_cache_create(const char * name, size_t size, void(*ctor)(void *), void(*dtor)(void *))
{
    WaitForSingleObject(mutex, INFINITE);

    if (size < 1) {
        print_error("Parametar size prosledjen funkciji kmem_cache_create ne moze biti manji od 1.\n");
        ReleaseMutex(mutex);
        return NULL;
    }

    if (cache_spot_list == NULL) {
        // Alociraj jedan blok za podatke o kesevima
        cache_spot_list = buddy_alloc(1);
        if (cache_spot_list == NULL) {
            print_error("Nedovoljno memorije za nastavak rada.\n");
            exit(-2);
        }

        int free_caches = BLOCK_SIZE / sizeof(kmem_cache_t);

        // Postavi pokazivace u listi na sledece prazno mesto
        for (int i = 0; i < free_caches - 1; i++) {
            (cache_spot_list + i)->next_cache = cache_spot_list + i + 1;
        }
        (cache_spot_list + free_caches - 1)->next_cache = NULL;
    }
    kmem_cache_t* handle = cache_spot_list; // Pravimo novi kes na slobodnoj lokaciji na koju ukazuje cache_spot_list
    cache_spot_list = cache_spot_list->next_cache; // Pokazivac na prvu slobodnu lokaciju postaje vrednost pokazivaca sledece slobodne lokacije

    handle->name = name;
    handle->obj_size = size;
    handle->constructor = ctor;
    handle->destructor = dtor;

    handle->expanded = 0;
    handle->err = 0;

    handle->empty_slabs = NULL;
    handle->mixed_slabs = NULL;
    handle->full_slabs = NULL;

    handle->next_cache = NULL;

    handle->next_offset = 0;

    int slab_size_in_blocks = size / BLOCK_SIZE + (size%BLOCK_SIZE?1:0);
    int used_size = (slab_size_in_blocks * BLOCK_SIZE / size) * size;
    int unused_size = slab_size_in_blocks * BLOCK_SIZE - used_size;

    handle->num_of_offsets = unused_size / CACHE_L1_LINE_SIZE + 1;

    // Povezi novi kes u listu keseva
    kmem_cache_t * temp = first_cache;
    if (temp != NULL) {
        while (temp->next_cache != NULL) temp = temp->next_cache;
        temp->next_cache = handle;
    }
    else {
        first_cache = handle;
    }

    ReleaseMutex(mutex);
    return handle;
}

int kmem_cache_shrink(kmem_cache_t * cachep)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * cache_temp = first_cache;
    while (cache_temp != NULL) {
        if (cache_temp == cachep) break;
        cache_temp = cache_temp->next_cache;
    }
    if (cache_temp == NULL) {
        print_error("Pokazivac na kes prosledjen funkciji kmem_cache_shrink nije validan.\n");
        ReleaseMutex(mutex);
        return NULL; // Nije pronadjen kes
    }

    int freed = 0;

    if (cachep->expanded != 1) {
        slabs* temp_slab = cachep->empty_slabs;
        while (temp_slab != NULL) {
            buddy_dealloc(temp_slab->slab, temp_slab->size_in_blocks);
            freed += temp_slab->size_in_blocks;
            cachep->empty_slabs = temp_slab->next_slab;

            temp_slab->next_slab = slab_spot_list;
            slab_spot_list = temp_slab;
            temp_slab = cachep->empty_slabs;
        }
    }
    cachep->expanded = 0;

    ReleaseMutex(mutex);
    return freed;
}

void * kmem_cache_alloc(kmem_cache_t * cachep)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * cache_temp = first_cache;
    while (cache_temp != NULL) {
        if (cache_temp == cachep) break;
        cache_temp = cache_temp->next_cache;
    }
    if (cache_temp == NULL) {
        print_error("Pokazivac na kes prosledjen funkciji kmem_cache_alloc nije validan.\n");
        ReleaseMutex(mutex);
        return NULL; // Nije pronadjen kes
    }

    unsigned char* free_addr = NULL;
    slabs* temp = NULL;

    if (cachep->mixed_slabs != NULL) {
        free_addr = cachep->mixed_slabs->free_spot;
        cachep->mixed_slabs->free_spot = *cachep->mixed_slabs->free_spot;
        if (cachep->mixed_slabs->free_spot == NULL) {
            // Prebaci plocu u pune ploce
            temp = cachep->mixed_slabs;
            cachep->mixed_slabs = cachep->mixed_slabs->next_slab;
            temp->next_slab = cachep->full_slabs;
            cachep->full_slabs = temp;
        }
    }
    else if (cachep->empty_slabs != NULL) {
        free_addr = cachep->empty_slabs->free_spot;
        cachep->empty_slabs->free_spot = *cachep->empty_slabs->free_spot;
        if (cachep->empty_slabs->free_spot == NULL) {
            // Prebaci plocu u pune ploce
            temp = cachep->empty_slabs;
            cachep->empty_slabs = cachep->empty_slabs->next_slab;
            temp->next_slab = cachep->full_slabs;
            cachep->full_slabs = temp;
        }
        else {
            // Prebaci plocu u polupune ploce
            temp = cachep->empty_slabs;
            cachep->empty_slabs = cachep->empty_slabs->next_slab;
            temp->next_slab = cachep->mixed_slabs;
            cachep->mixed_slabs = temp;
        }
    }
    else { // Alociraj novu plocu

        if (slab_spot_list == NULL) {
            // Alociraj jedan blok za podatke o plocama
            slab_spot_list = buddy_alloc(1);
            if (slab_spot_list == NULL) {
                print_error("Nedovoljno memorije za nastavak rada.\n");
                exit(-2);
            }

            int free_slabs = BLOCK_SIZE / sizeof(slabs);

            // Postavi pokazivace u listi na sledece prazno mesto
            for (int i = 0; i < free_slabs - 1; i++) {
                (slab_spot_list + i)->next_slab = slab_spot_list + (i + 1);
            }
            (slab_spot_list + free_slabs - 1)->next_slab = NULL;
        }

        int size_needed = cachep->obj_size / BLOCK_SIZE + (cachep->obj_size%BLOCK_SIZE ? 1 : 0);

        slabs* new_slab = slab_spot_list;
        slab_spot_list = slab_spot_list->next_slab;

        new_slab->slab = buddy_alloc(size_needed);
        if (new_slab->slab == NULL) {
            print_error("Nedovoljno memorije za nastavak rada.\n");
            exit(-2);
        }
        new_slab->size_in_blocks = size_needed;

        new_slab->L1_offset = cachep->next_offset * CACHE_L1_LINE_SIZE;
        cachep->next_offset = (cachep->next_offset + 1) % cachep->num_of_offsets;

        new_slab->free_spot = (char*)new_slab->slab + new_slab->L1_offset;

        int size = cachep->obj_size < 4 ? 4 : cachep->obj_size;

        int obj_free_spots = new_slab->size_in_blocks * BLOCK_SIZE / size;
        // Postavi pokazivace u listi na sledece prazno mesto
        for (int i = 0; i < obj_free_spots - 1; i++) {
            *(int*)((char*)new_slab->free_spot + i * size) = (char*)new_slab->free_spot + (i + 1) * size;
        }
        *(int*)((char*)new_slab->free_spot + (obj_free_spots - 1) * size) = NULL;

        new_slab->next_slab = cachep->mixed_slabs;
        cachep->mixed_slabs = new_slab; // Posto ce objekat odmah biti alociran u ploci, direktno je ubaci u litu polupunih ploca

        free_addr = cachep->mixed_slabs->free_spot;
        cachep->mixed_slabs->free_spot = *cachep->mixed_slabs->free_spot;
        if (cachep->mixed_slabs->free_spot == NULL) {
            // Prebaci plocu u pune ploce
            temp = cachep->mixed_slabs;
            cachep->mixed_slabs = cachep->mixed_slabs->next_slab;
            temp->next_slab = cachep->full_slabs;
            cachep->full_slabs = temp;
        }

        cachep->expanded = 1;
    }

    if (cachep->constructor != NULL)
        cachep->constructor(free_addr);
    ReleaseMutex(mutex);
    return free_addr;
}

void kmem_cache_free(kmem_cache_t * cachep, void * objp)
{

    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * cache_temp = first_cache;
    while (cache_temp != NULL) {
        if (cache_temp == cachep) break;
        cache_temp = cache_temp->next_cache;
    }
    if (cache_temp == NULL) {
        print_error("Pokazivac na kes prosledjen funkciji kmem_cache_free nije validan.\n");
        ReleaseMutex(mutex);
        return; // Nije pronadjen kes
    }

    // Pronalazenje objekta u plocama
    slabs* temp = cachep->mixed_slabs;
    int in_mixed_slabs = 0;
    while (temp != NULL) {
        if ((char*)temp->slab <= (char*)objp) {
            if ((char*)objp < ((char*)temp->slab + temp->size_in_blocks*BLOCK_SIZE)) {
                in_mixed_slabs = 1;
                break;
            }
        }
        temp = temp->next_slab;
    }
    if (temp == NULL) { // Adresa nije u polupunim plocama, proveri pune
        temp = cachep->full_slabs;
        while (temp != NULL) {
            if ((char*)temp->slab <= (char*)objp) {
                if ((char*)objp < ((char*)temp->slab + temp->size_in_blocks*BLOCK_SIZE)) {
                    break;
                }
            }
            temp = temp->next_slab;
        }
    }
    if (temp == NULL) { // Objekat nije ni u jednoj ploci
        print_error("Pokazivac na objekat prosledjen funkciji kmem_cache_free nije validan.\n");
        cachep->err = 1;
        ReleaseMutex(mutex);
        return;
    }
    else {
        int size = cachep->obj_size < 4 ? 4 : cachep->obj_size;
        if (abs((char*)objp - (char*)temp->slab - temp->L1_offset) % size != 0) {
            print_error("Pokazivac na objekat prosledjen funkciji kmem_cache_free nije validan.\n");
            ReleaseMutex(mutex);
            return;
        }

        int* iterS = temp->free_spot;
        while (iterS != NULL) {
            if (iterS == temp) break;
            else iterS = *iterS;

        }
        if (iterS != NULL) {
            print_error("Pokazivac na objekat prosledjen funkciji kmem_cache_free nije validan.\n");
            ReleaseMutex(mutex);
            return;
        }
    }

    if (cachep->destructor != NULL) cachep->destructor(objp);
    *((int*)objp) = temp->free_spot;
    temp->free_spot = (int*)objp;

    // Proveri da li je ploca postala prazna
    int num_of_objs = temp->size_in_blocks * BLOCK_SIZE / cachep->obj_size;
    int* iter = temp->free_spot;
    slabs* prev = NULL;

    while (iter != NULL) {
        num_of_objs--;
        iter = *iter;
    }
    if (num_of_objs == 0) { // Sva mesta su slobodna, ploca je prazna
        if (in_mixed_slabs == 1) prev = cachep->mixed_slabs;
        else prev = cachep->full_slabs;

        if (prev == temp) prev = NULL;
        else while (prev->next_slab != temp) prev = prev->next_slab;

        // Prebaci plocu u prazne ploce
        if (prev == NULL) { // Ploca koja se izbacuje je prva u nizu
            if (in_mixed_slabs == 1) {
                cachep->mixed_slabs = cachep->mixed_slabs->next_slab;
                temp->next_slab = cachep->empty_slabs;
                cachep->empty_slabs = temp;
            }
            else {
                cachep->full_slabs = cachep->full_slabs->next_slab;
                temp->next_slab = cachep->empty_slabs;
                cachep->empty_slabs = temp;
            }
        }
        else {
            prev->next_slab = temp->next_slab;
            temp->next_slab = cachep->empty_slabs;
            cachep->empty_slabs = temp;

        }
    }
    else {
        if (in_mixed_slabs == 0) {
            prev = cachep->full_slabs;

            if (prev == temp) prev = NULL;
            else while (prev->next_slab != temp) prev = prev->next_slab;

            // Prebaci plocu u prazne ploce
            if (prev == NULL) { // Ploca koja se izbacuje je prva u nizu

                cachep->full_slabs = cachep->full_slabs->next_slab;
                temp->next_slab = cachep->mixed_slabs;
                cachep->mixed_slabs = temp;

            }
            else {
                prev->next_slab = temp->next_slab;
                temp->next_slab = cachep->mixed_slabs;
                cachep->mixed_slabs = temp;

            }
        }
    }

    ReleaseMutex(mutex);
}

void * kmalloc(size_t size)
{
    if (size < 32) {
        print_error("Nije moguce alocirati memorijski bafer manji od 32B");
        return NULL;
    }
    else if (size > 131072) {
        print_error("Nije moguce alocirati memorijski baffer veci od 128KB");
        return NULL;
    }

    WaitForSingleObject(mutex, INFINITE);

    int next_pow2 = (int)ceil(log(size) / log(2));
    int next2 = (int)pow(2, next_pow2);

    char* name = names + (next_pow2 - 5) * 8;
    kmem_cache_t* temp = first_cache;
    while (temp != NULL) {
        if (strcmp(temp->name, name) != 0) {
            temp = temp->next_cache;
        }
        else break;
    }

    if (temp == NULL) { // Kes za memorijske bafere velicine size jos uvek nije kreiran
        temp = kmem_cache_create(name, next2, NULL, NULL); // Napravi novi kes
    }

    void* adr = kmem_cache_alloc(temp);

    ReleaseMutex(mutex);
    return adr;
}

void kfree(const void * objp)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t* cache = first_cache;
    slabs* slab = NULL;
    int found = 0;
    int in_mixed_slabs = 0;
    while (found == 0 && cache != NULL) {
        // Pronalazenje objekta u plocama
        slab = cache->mixed_slabs;
        while (slab != NULL) {
            if (slab->slab <= objp) {
                if (objp < ((char*)slab->slab + slab->size_in_blocks*BLOCK_SIZE)) {
                    found = 1;
                    in_mixed_slabs = 1;
                    break;
                }
            }
            slab = slab->next_slab;
        }
        if (slab == NULL) { // Adresa nije u polupunim plocama, proveri pune
            slab = cache->full_slabs;
            while (slab != NULL) {
                if (slab->slab <= objp) {
                    if (objp < ((char*)slab->slab + slab->size_in_blocks*BLOCK_SIZE)) {
                        found = 1;
                        break;
                    }
                }
                slab = slab->next_slab;
            }
        }
        if (found == 0) cache = cache->next_cache;
    }
    if (found == 1) {
        int size = cache->obj_size < 4 ? 4 : cache->obj_size;
        if (abs((char*)objp - (char*)slab->slab - slab->L1_offset) % size != 0) {
            print_error("Pokazivac na objekat prosledjen funkciji kmem_cache_free nije validan.\n");
            ReleaseMutex(mutex);
            return;
        }

        int* iterS = slab->free_spot;
        while (iterS != NULL) {
            if (iterS == slab) break;
            else iterS = *iterS;

        }
        if (iterS != NULL) {
            print_error("Pokazivac na objekat prosledjen funkciji kmem_cache_free nije validan.\n");
            ReleaseMutex(mutex);
            return;
        }
        *((int*)objp) = slab->free_spot;
        slab->free_spot = (int*)objp;


        // Proveri da li je ploca postala prazna
        int num_of_objs = slab->size_in_blocks * BLOCK_SIZE / cache->obj_size;
        int* iter = slab->free_spot;
        slabs* prev = NULL;

        while (iter != NULL) {
            num_of_objs--;
            iter = *iter;
        }
        if (num_of_objs == 0) { // Svi mesta su slobodna, ploca je prazna
            if (in_mixed_slabs == 1) prev = cache->mixed_slabs;
            else prev = cache->full_slabs;

            if (prev == slab) prev = NULL;
            else while (prev->next_slab != slab) prev = prev->next_slab;


            // Prebaci plocu u prazne ploce
            if (prev == NULL) { // Ploca koja se izbacuje je prva u nizu
                if (in_mixed_slabs == 1) {
                    cache->mixed_slabs = cache->mixed_slabs->next_slab;
                    slab->next_slab = cache->empty_slabs;
                    cache->empty_slabs = slab;
                }
                else {
                    cache->full_slabs = cache->full_slabs->next_slab;
                    slab->next_slab = cache->empty_slabs;
                    cache->empty_slabs = slab;
                }
            }
            else {

                prev->next_slab = slab->next_slab;
                slab->next_slab = cache->empty_slabs;
                cache->empty_slabs = slab;

            }
        }
        else {
            if (in_mixed_slabs == 0) {
                prev = cache->full_slabs;

                if (prev == slab) prev = NULL;
                else while (prev->next_slab != slab) prev = prev->next_slab;


                // Prebaci plocu u prazne ploce
                if (prev == NULL) { // Ploca koja se izbacuje je prva u nizu

                    cache->full_slabs = cache->full_slabs->next_slab;
                    slab->next_slab = cache->mixed_slabs;
                    cache->mixed_slabs = slab;

                }
                else {

                    prev->next_slab = slab->next_slab;
                    slab->next_slab = cache->mixed_slabs;
                    cache->mixed_slabs = slab;

                }
            }
        }
    }
    else { // Adresa nije ni u jednom kesu
        print_error("Dostavljena adresa funckiji za dealociranje memorijskog bafera nije validna.\n");
    }

    ReleaseMutex(mutex);
}

void kmem_cache_destroy(kmem_cache_t * cachep)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * prev = first_cache;
    if (prev != cachep) {
        while (prev->next_cache != cachep) {
            if (prev->next_cache == NULL) {
                print_error("Pokazivac na kes prosledjen funkciji kmem_cache_destroy nije validan.\n");
                ReleaseMutex(mutex);
                return; // Nije pronadjen kes
            }
            prev = prev->next_cache;
        }
    }
    // Unisti liste slabova
    slabs* temp_slab = cachep->empty_slabs;
    while (temp_slab != NULL) {
        buddy_dealloc(temp_slab->slab, temp_slab->size_in_blocks);
        cachep->empty_slabs = temp_slab->next_slab;

        temp_slab->next_slab = slab_spot_list;
        slab_spot_list = temp_slab;
        temp_slab = cachep->empty_slabs;
    }
    temp_slab = cachep->mixed_slabs;
    while (temp_slab != NULL) {
        buddy_dealloc(temp_slab->slab, temp_slab->size_in_blocks);
        cachep->mixed_slabs = temp_slab->next_slab;

        temp_slab->next_slab = slab_spot_list;
        slab_spot_list = temp_slab;
        temp_slab = cachep->mixed_slabs;
    }
    temp_slab = cachep->full_slabs;
    while (temp_slab != NULL) {
        buddy_dealloc(temp_slab->slab, temp_slab->size_in_blocks);
        cachep->full_slabs = temp_slab->next_slab;

        temp_slab->next_slab = slab_spot_list;
        slab_spot_list = temp_slab;
        temp_slab = cachep->full_slabs;
    }

    // Izbaci iz liste keseva
    if (cachep == first_cache) {
        first_cache = first_cache->next_cache;
    }
    else {
        prev->next_cache = prev->next_cache->next_cache;
    }

    cachep->next_cache = NULL;

    // Dodaj lokaciju u listu slobodnih mesta za keseve
    cachep->next_cache = cache_spot_list;
    cache_spot_list = cachep;

    ReleaseMutex(mutex);
}

void kmem_cache_info(kmem_cache_t * cachep)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * cache_temp = first_cache;
    while (cache_temp != NULL) {
        if (cache_temp == cachep) break;
        cache_temp = cache_temp->next_cache;
    }
    if (cache_temp == NULL) {
        print_error("Pokazivac na kes prosledjen funkciji kmem_cache_info nije validan.\n");
        ReleaseMutex(mutex);
        return; // Nije pronadjen kes
    }

    int slabs_num = 0;
    int temp = 0;
    slabs* iter = cachep->empty_slabs;
    while (iter != NULL) {
        slabs_num++;
        iter = iter->next_slab;
    }
    iter = cachep->mixed_slabs;
    while (iter != NULL) {
        slabs_num++;
        iter = iter->next_slab;
    }
    iter = cachep->full_slabs;
    temp = slabs_num; // Broj praznih i polupraznih ploca
    while (iter != NULL) {
        slabs_num++;
        iter = iter->next_slab;
    }

    int slab_size_in_blocks = cachep->obj_size / BLOCK_SIZE + (cachep->obj_size%BLOCK_SIZE ? 1 : 0);
    int size = cachep->obj_size < 4 ? 4 : cachep->obj_size;
    int objs_num = slab_size_in_blocks * BLOCK_SIZE / size;

    int max_objects = slabs_num * objs_num;
    int objects = (slabs_num - temp) * objs_num;

    slabs* temp_slab = cachep->mixed_slabs;
    while (temp_slab != NULL) {
        int* iter = temp_slab->free_spot;

        objects += objs_num;

        while (iter != NULL) {
            objects--;
            iter = *iter;
        }

        temp_slab = temp_slab->next_slab;
    }

    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    // Ispis imena
    print_info("Cache: ");
    printf_s("%s\t", cachep->name);

    // Ispis velicine objekta
    print_info("Object size: ");
    printf_s("%d\t", cachep->obj_size);

    // Ispis broja blokova
    print_info("Block count: ");
    printf_s("%d\t", slabs_num * slab_size_in_blocks);

    // Ispis broja ploca
    print_info("Slab count: ");
    printf_s("%d\t", slabs_num);

    // Ispis broja objekata po ploci
    print_info("Objects per slab: ");
    printf_s("%d\t", objs_num);

    // Ispis procenta popunjnosti
    print_info("Occupied: ");
    if (max_objects ) printf_s("%d%%\n", (int)(objects * 100.0 / max_objects));
    else printf_s("-\n");
    ReleaseMutex(mutex);
}

int kmem_cache_error(kmem_cache_t * cachep)
{
    WaitForSingleObject(mutex, INFINITE);

    kmem_cache_t * cache_temp = first_cache;
    while (cache_temp != NULL) {
        if (cache_temp == cachep) break;
        cache_temp = cache_temp->next_cache;
    }
    if (cache_temp == NULL) {
        print_error("Pokazivac na kes prosledjen funkciji kmem_cache_error nije validan.\n");
        ReleaseMutex(mutex);
        return; // Nije pronadjen kes
    }

    if (cachep->err == 0) printf_s("Nije bilo greski u radu sa kesom.\n");
    else printf_s("U kesu je bio pokusaj dealokacije objekta koji mu ne pripada");

    ReleaseMutex(mutex);
    return 0;
}