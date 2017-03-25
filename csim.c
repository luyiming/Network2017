/**
 * 151220066
 * 陆依鸣
 */

#include "cachelab.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>

struct globalArgs_t {
    int set_bits;
    int col_bits;
    int row_size;
    int set_size;
    int col_size;
    int cache_size;
    const char *inputFile;
    int v;
} globalArgs;

static const char *optString = "s:E:b:t:v";
const int MAXN = 100;

typedef struct cacheBlock_t {
    uint32_t tag;
    int valid;
} cacheBlock;
cacheBlock *cache;

// LRU algorithm uses LRU_list(linked-list) to determine which cache_block to be replaced
// the Least Recently Used cache_block is always the last LRUNode in LRU_list
// every time a cache_block is visited, it will be moved to the front of LRU_list
typedef struct LRUNode_t {
    struct LRUNode_t* next;
    int idx;
} LRUNode;
LRUNode *LRU_list;


int hit_count, miss_count, eviction_count;

/**
 * parse command options
 * @method parse_opt
 * @param  argc      [main argc]
 * @param  argv      [main argv]
 */
void parse_opt(int argc, char **argv) {
    globalArgs.v = 0;
    globalArgs.inputFile = NULL;
    int opt = getopt(argc, argv, optString);
    while (opt != -1) {
        switch (opt) {
            case 's':
                globalArgs.set_bits = atoi(optarg);
                globalArgs.set_size = 1 << globalArgs.set_bits;
                break;
            case 'E':
                globalArgs.row_size = atoi(optarg);
                break;
            case 'b':
                globalArgs.col_bits = atoi(optarg);
                globalArgs.col_size = 1 << globalArgs.col_bits;
                break;
            case 't':
                globalArgs.inputFile = optarg;
                break;
            case 'v':
                globalArgs.v = 1;
                break;
            default:
                /* You won't actually get here. */
                break;
        }
        opt = getopt(argc, argv, optString);
    }
    globalArgs.cache_size = globalArgs.row_size * globalArgs.set_size;
}

/**
 * parse hexadecimal address
 * @method parse_addr
 * @param  p          [string to be parsed]
 * @return            [cache address]
 */
uint32_t parse_addr(char *p) {
    uint32_t addr = 0;
    char *q;
    p = strchr(p, ' ') + 1;
    for (q = strchr(p, ','); p < q; p++) {
        if (*p >= '0' && *p <= '9') {
            addr = addr * 16 + *p - '0';
        }
        else {
            addr = addr * 16 + *p - 'a' + 10;
        }
    }
    return addr;
}

/**
 * debug LRU_list
 * @method debug_list
 */
void debug_list() {
    for (int i = 0; i < globalArgs.set_size; i++) {
        printf("set %d: ", i);
        LRUNode *p = LRU_list[i].next;
        while (p != NULL) {
            printf("%d/%d -> ", p->idx, cache[p->idx].valid);
            p = p->next;
        }
        printf("NULL\n");
    }
}

/**
 * initialize cache & LRU_list
 * @method init_cache
 */
void init_cache() {
    cache = (cacheBlock*)malloc(sizeof(cacheBlock) * globalArgs.cache_size);
    LRU_list = (LRUNode*)malloc(sizeof(LRUNode) * globalArgs.set_size);
    for (int i = 0; i < globalArgs.set_size; ++i) {
        LRU_list[i] = *(LRUNode*)malloc(sizeof(LRUNode));
        LRU_list[i].next = NULL;
    }
    for (int i = 0; i < globalArgs.cache_size; ++i) {
        cache[i].valid = 0;
        LRUNode *t = (LRUNode*)malloc(sizeof(LRUNode));
        t->idx = i;
        t->next = LRU_list[i / globalArgs.row_size].next;
        LRU_list[i / globalArgs.row_size].next = t;
    }
}

/**
 * simulate cache visiting
 * @method visit_cache
 * @param  addr     [cache address]
 * @param  count    [cache visit times] L,S:1  M:2
 */
void visit_cache(uint32_t addr, int count) {
    uint32_t set_addr = addr >> globalArgs.col_bits;
    uint32_t tag = set_addr >> globalArgs.set_bits;
    set_addr = set_addr & ((1 << globalArgs.set_bits) - 1);
    int set_start = set_addr * globalArgs.row_size;
    for (int i = set_start; i < set_start + globalArgs.row_size; i++) {
        if (cache[i].valid == 1 && cache[i].tag == tag) {
            LRUNode *q = &LRU_list[i / globalArgs.row_size], *p = q->next;
            while (p != NULL) {
                if (p->idx == i)
                    break;
                else {
                    q = p;
                    p = p->next;
                }
            }
            if (q != &LRU_list[i / globalArgs.row_size]) {
                q->next = p->next;
                p->next = LRU_list[i / globalArgs.row_size].next;
                LRU_list[i / globalArgs.row_size].next = p;
            }
            hit_count += count;
            if (globalArgs.v == 1) {
                while (count--)
                    printf("hit ");
                printf("\n");
            }
            return;
        }
    }

    LRUNode *q = &LRU_list[set_addr], *p = q->next;
    while (p->next != NULL) {
        q = p;
        p = p->next;
    }
    if (cache[p->idx].valid == 0) {
        miss_count += 1;
        hit_count += (count - 1);
        if (globalArgs.v == 1) {
            if (count == 1)
                printf("miss\n");
            else
                printf("miss hit\n");
        }

    }
    else {
        eviction_count += 1;
        miss_count += 1;
        hit_count += (count - 1);
        if (globalArgs.v == 1) {
            if (count == 1)
                printf("miss eviction\n");
            else
                printf("miss eviction hit\n");
        }
    }
    cache[p->idx].valid = 1;
    cache[p->idx].tag = tag;
    q->next = NULL;
    p->next = LRU_list[set_addr].next;
    LRU_list[set_addr].next = p;
    return;
}



int main(int argc, char **argv)
{
    parse_opt(argc, argv);
    init_cache();
    hit_count = miss_count = eviction_count = 0;

    char line[MAXN], *p;
    uint32_t addr = 0;
    FILE *fp = fopen(globalArgs.inputFile, "r");
    while (!feof(fp)) {
        fgets(line, MAXN, fp);
        if (feof(fp))
            break;
        if (globalArgs.v == 1) {
            printf("%s", line);
        }
        p = line;
        while (p != NULL) {
            if (*p == 'I') {
                if (globalArgs.v == 1) {
                    printf("skip\n");
                }
                break;
            }
            else if (*p == 'L' || *p == 'S') {
                addr = parse_addr(p);
                visit_cache(addr, 1);
                break;
            }
            else if (*p == 'M') {
                addr = parse_addr(p);
                visit_cache(addr, 2);
                break;
            }
            else {
                p++;
            }
        }
    }

    fclose(fp);
    free(cache);
    printSummary(hit_count, miss_count, eviction_count);
    return 0;
}
