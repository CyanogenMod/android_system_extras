/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>

typedef struct {
    unsigned char x;
    unsigned char y;
    unsigned char z;
    unsigned char w;
} uchar4;

typedef struct {
    float x;
    float y;
    float z;
    float w;
} float4;


#define MAX_RADIUS 25
#define WIDTH 512
#define HEIGHT 512

uchar4 bufIn[WIDTH * HEIGHT];
uchar4 bufOut[WIDTH * HEIGHT];
uchar4 bufTmp[WIDTH * HEIGHT];

static float gaussian[MAX_RADIUS * 2 + 1];
static int height = 512;
static int width = 512;
static int radius = MAX_RADIUS;



static void horiz(uchar4 *output, const uchar4 *inputBuf, uint32_t x, uint32_t y) {
    const uchar4 *input = inputBuf + (y * width);
    float4 blurredPixel = {0,0,0,0};
    float4 currentPixel;

    for(int r = -radius; r <= radius; r ++) {
        // Stepping left and right away from the pixel
        int validW = x + r;
        // Clamp to zero and width max() isn't exposed for ints yet
        if(validW < 0) {
            validW = 0;
        }
        if(validW > WIDTH - 1) {
            validW = WIDTH - 1;
        }
        //int validW = rsClamp(w + r, 0, width - 1);

        float weight = gaussian[r + radius];
        currentPixel.x = (float)(input[validW].x);
        currentPixel.y = (float)(input[validW].y);
        currentPixel.z = (float)(input[validW].z);
        //currentPixel.w = (float)(input->a);

        blurredPixel.x += currentPixel.x * weight;
        blurredPixel.y += currentPixel.y * weight;
        blurredPixel.z += currentPixel.z * weight;
    }

    output->x = (uint8_t)blurredPixel.x;
    output->y = (uint8_t)blurredPixel.y;
    output->z = (uint8_t)blurredPixel.z;
}


static void vert(uchar4 *output, const uchar4 *inputBuf, uint32_t x, uint32_t y) {
    const uchar4 *input = inputBuf + x;

    float4 blurredPixel = {0,0,0,0};

    float4 currentPixel;
    for(int r = -radius; r <= radius; r ++) {
        int validH = y + r;
        // Clamp to zero and width
        if(validH < 0) {
            validH = 0;
        }
        if(validH > HEIGHT - 1) {
            validH = HEIGHT - 1;
        }

        const uchar4 *i = input + validH * WIDTH;

        float weight = gaussian[r + radius];

        currentPixel.x = (float)(i->x);
        currentPixel.y = (float)(i->y);
        currentPixel.z = (float)(i->z);

        blurredPixel.x += currentPixel.x * weight;
        blurredPixel.y += currentPixel.y * weight;
        blurredPixel.z += currentPixel.z * weight;
    }

    //output->xyz = convert_uchar3(blurredPixel.xyz);
    output->x = (uint8_t)blurredPixel.x;
    output->y = (uint8_t)blurredPixel.y;
    output->z = (uint8_t)blurredPixel.z;
}


typedef long long nsecs_t;

static nsecs_t system_time()
{
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return nsecs_t(t.tv_sec)*1000000000LL + t.tv_nsec;
}

int fp_test(int argc, char** argv) {
    for (int ct=0; ct < (sizeof(gaussian)/4); ct++) {
        gaussian[ct] = 1.f;
    }
    memset(bufIn, 0, sizeof(bufIn));

    nsecs_t t1 = system_time();

    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++) {
            horiz(&bufTmp[x + y * WIDTH], bufIn, x, y);
        }
    }

    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++) {
            vert(&bufOut[x + y * WIDTH], bufTmp, x, y);
        }
    }

    nsecs_t t2 = system_time();

    printf("FP Test time %i ms\n", (int)((t2 - t1) / 1000000) );

    return 0;
}

