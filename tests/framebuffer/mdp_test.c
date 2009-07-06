/*
 * Copyright (C) 2007 Google Inc.
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

#include <fcntl.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/fb.h>
#include <linux/msm_mdp.h>

static struct fb_var_screeninfo vi;

static int get_framebuffer(int *fd, char **fb, int *width, int *height)
{
    struct fb_fix_screeninfo fi;
    void *bits;

    *fd = open("/dev/graphics/fb0", O_RDWR);
    if(*fd < 0) {
        perror("cannot open fb0");
        return -1;
    }

    if(ioctl(*fd, FBIOGET_FSCREENINFO, &fi) < 0) {
        perror("failed to get fb0 info");
        return -1;
    }

    if(ioctl(*fd, FBIOGET_VSCREENINFO, &vi) < 0) {
        perror("failed to get fb0 info");
        return -1;
    }

    bits = mmap(0, fi.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if(bits == MAP_FAILED) {
        perror("failed to mmap framebuffer");
        return -1;
    }

    *width = vi.xres;
    *height = vi.yres;
    *fb = bits;
    return 0;
}

static void set_active_framebuffer(int fd, unsigned n)
{

    if(n > 1) return;
    vi.yres_virtual = vi.yres * 2;
    vi.yoffset = n * vi.yres;
    if(ioctl(fd, FBIOPUT_VSCREENINFO, &vi) < 0) {
        fprintf(stderr,"active fb swap failed!\n");
    }
}

int main(int argc, const char *argv[]) {
    int fd, width, height;
    char* fb;
    struct mdp_blit_req_list *req_list;
    struct mdp_blit_req *req;
    int srw, srh, drw, drh;
    int srcx = 0; int srcy = 0;
    int dstx = 10; int dsty = 10;

    req_list = malloc(sizeof(struct mdp_blit_req_list) +
                      sizeof(struct mdp_blit_req));
    req_list->count = 1;
    req = req_list->req;

    if (argc < 5)
        printf("not enough args\n");
    srw = atoi(argv[1]);
    srh = atoi(argv[2]);
    drw = atoi(argv[3]);
    drh = atoi(argv[4]);

    if (argc >= 7) {
        srcx = atoi(argv[5]);
        srcy = atoi(argv[6]);
    }

    if (argc == 9) {
        dstx = atoi(argv[7]);
        dsty = atoi(argv[8]);
    }


    if (get_framebuffer(&fd, &fb, &width, &height)) {
        printf("couldnt' get fb\n");
        return -1;
    }
    /*
       req->src.width = 448;
       req->src.height = 320;
       */
    req->src.width = vi.xres;
    req->src.height = vi.yres;
    req->src.format = MDP_RGB_565/*MDP_Y_CBCR_H2V2*/;
    req->src.offset = 0;
    req->src.memory_id = fd;
    req->src_rect.x = srcx;
    req->src_rect.y = srcy;
    req->src_rect.w = srw;
    req->src_rect.h = srh;

    req->dst.width = vi.xres;
    req->dst.height = vi.yres;
    req->dst.format = MDP_RGB_565;
    req->dst.offset = 0;
    req->dst.memory_id = fd;
    req->dst_rect.x = dstx;
    req->dst_rect.y = dsty;
    req->dst_rect.w = drw;
    req->dst_rect.h = drh;
    req->alpha = MDP_ALPHA_NOP;
    req->transp_mask = MDP_TRANSP_NOP;
//    req->flags = MDP_ROT_90;
    req->flags = MDP_ROT_NOP;

    if(ioctl(fd, MSMFB_BLIT, req_list))
        fprintf(stderr, "crap, failed blit\n");
    return 0;
}
