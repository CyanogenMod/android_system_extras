/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <unistd.h>

#include <pagemap/pagemap.h>

#define SIMPLEQ_INSERT_SIMPLEQ_TAIL(head_a, head_b)             \
    do {                                                        \
        if (!SIMPLEQ_EMPTY(head_b)) {                           \
            if ((head_a)->sqh_first == NULL)                    \
                (head_a)->sqh_first = (head_b)->sqh_first;      \
            *(head_a)->sqh_last = (head_b)->sqh_first;          \
            (head_a)->sqh_last = (head_b)->sqh_last;            \
        }                                                       \
    } while (/*CONSTCOND*/0)

/* We use an array of int to store the references to a given offset in the swap
   1 GiB swap means 512KiB size array: offset are the index */
typedef unsigned short pm_pswap_refcount_t;
struct pm_proportional_swap {
    unsigned int array_size;
    pm_pswap_refcount_t *offset_array;
};

void pm_memusage_zero(pm_memusage_t *mu) {
    mu->vss = mu->rss = mu->pss = mu->uss = mu->swap = 0;
    mu->p_swap = NULL;
    SIMPLEQ_INIT(&mu->swap_offset_list);
}

void pm_memusage_pswap_init_handle(pm_memusage_t *mu, pm_proportional_swap_t *p_swap) {
    mu->p_swap = p_swap;
}

void pm_memusage_add(pm_memusage_t *a, pm_memusage_t *b) {
    a->vss += b->vss;
    a->rss += b->rss;
    a->pss += b->pss;
    a->uss += b->uss;
    a->swap += b->swap;
    SIMPLEQ_INSERT_SIMPLEQ_TAIL(&a->swap_offset_list, &b->swap_offset_list);
}

pm_proportional_swap_t * pm_memusage_pswap_create(int swap_size)
{
    pm_proportional_swap_t *p_swap = NULL;

    p_swap = malloc(sizeof(pm_proportional_swap_t));
    if (p_swap == NULL) {
        fprintf(stderr, "Error allocating proportional swap.\n");
    } else {
        p_swap->array_size = swap_size / getpagesize();
        p_swap->offset_array = calloc(p_swap->array_size, sizeof(pm_pswap_refcount_t));
        if (p_swap->offset_array == NULL) {
            fprintf(stderr, "Error allocating proportional swap offset array.\n");
            free(p_swap);
            p_swap = NULL;
        }
    }

    return p_swap;
}

void pm_memusage_pswap_destroy(pm_proportional_swap_t *p_swap) {
    if (p_swap) {
        free(p_swap->offset_array);
        free(p_swap);
    }
}

void pm_memusage_pswap_add_offset(pm_memusage_t *mu, unsigned int offset) {
    pm_swap_offset_t *soff;

    if (mu->p_swap == NULL)
        return;

    if (offset > mu->p_swap->array_size) {
        fprintf(stderr, "SWAP offset %d is out of swap bounds.\n", offset);
        return;
    } else {
        if (mu->p_swap->offset_array[offset] == USHRT_MAX) {
            fprintf(stderr, "SWAP offset %d ref. count if overflowing ushort type.\n", offset);
        } else {
            mu->p_swap->offset_array[offset]++;
        }
    }

    soff = malloc(sizeof(pm_swap_offset_t));
    if (soff) {
        soff->offset = offset;
        SIMPLEQ_INSERT_TAIL(&mu->swap_offset_list, soff, simpleqe);
    }
}

void pm_memusage_pswap_get_usage(pm_memusage_t *mu, pm_swapusage_t *su) {

    int pagesize = getpagesize();
    pm_swap_offset_t *elem;

    if (su == NULL)
        return;

    su->proportional = su->unique = 0;
    SIMPLEQ_FOREACH(elem, &mu->swap_offset_list, simpleqe) {
        su->proportional += pagesize / mu->p_swap->offset_array[elem->offset];
        su->unique += mu->p_swap->offset_array[elem->offset] == 1 ? pagesize : 0;
    }
}

void pm_memusage_pswap_free(pm_memusage_t *mu) {
    pm_swap_offset_t *elem = SIMPLEQ_FIRST(&mu->swap_offset_list);
    while (elem) {
        SIMPLEQ_REMOVE_HEAD(&mu->swap_offset_list, simpleqe);
        free(elem);
        elem = SIMPLEQ_FIRST(&mu->swap_offset_list);
    }
}
