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

#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>

#include <linux/fb.h>
#include <linux/kd.h>

#include <pixelflinger/pixelflinger.h>

#include "minui.h"

typedef struct {
    GGLSurface texture;
    unsigned cwidth;
    unsigned cheight;
    unsigned ascent;
} GRFont;

static GGLContext *gr_context = 0;
static GGLSurface gr_framebuffer[2];
static unsigned gr_active_fb = 0;

static int gr_fb_fd = -1;
static int gr_vt_fd = -1;

static struct fb_var_screeninfo vi;
struct fb_fix_screeninfo fi;
struct timespec tv, tv2;

static void dumpinfo(struct fb_fix_screeninfo *fi,
                     struct fb_var_screeninfo *vi);

static int get_framebuffer(GGLSurface *fb)
{
    int fd;
    void *bits;

    fd = open("/dev/graphics/fb0", O_RDWR);
    if (fd < 0) {
        printf("cannot open /dev/graphics/fb0, retrying with /dev/fb0\n");
        if ((fd = open("/dev/fb0", O_RDWR)) < 0) {
            perror("cannot open /dev/fb0");
            return -1;
        }
    }

    if(ioctl(fd, FBIOGET_FSCREENINFO, &fi) < 0) {
        perror("failed to get fb0 info");
        return -1;
    }

    if(ioctl(fd, FBIOGET_VSCREENINFO, &vi) < 0) {
        perror("failed to get fb0 info");
        return -1;
    }

    dumpinfo(&fi, &vi);

    bits = mmap(0, fi.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(bits == MAP_FAILED) {
        perror("failed to mmap framebuffer");
        return -1;
    }

    fb->version = sizeof(*fb);
    fb->width = vi.xres;
    fb->height = vi.yres;
    fb->stride = fi.line_length / (vi.bits_per_pixel >> 3);
    fb->data = bits;
    fb->format = GGL_PIXEL_FORMAT_RGB_565;

    fb++;

    fb->version = sizeof(*fb);
    fb->width = vi.xres;
    fb->height = vi.yres;
    fb->stride = fi.line_length / (vi.bits_per_pixel >> 3);
    fb->data = (void*) (((unsigned) bits) + vi.yres * vi.xres * 2);
    fb->format = GGL_PIXEL_FORMAT_RGB_565;

    return fd;
}

static void set_active_framebuffer(unsigned n)
{
    if(n > 1) return;
    vi.yres_virtual = vi.yres * 2;
    vi.yoffset = n * vi.yres;
    if(ioctl(gr_fb_fd, FBIOPUT_VSCREENINFO, &vi) < 0) {
        fprintf(stderr,"active fb swap failed!\n");
    } else
        printf("active buffer: %d\n", n);
}

static void dumpinfo(struct fb_fix_screeninfo *fi, struct fb_var_screeninfo *vi)
{
    fprintf(stderr,"vi.xres = %d\n", vi->xres);
    fprintf(stderr,"vi.yres = %d\n", vi->yres);
    fprintf(stderr,"vi.xresv = %d\n", vi->xres_virtual);
    fprintf(stderr,"vi.yresv = %d\n", vi->yres_virtual);
    fprintf(stderr,"vi.xoff = %d\n", vi->xoffset);
    fprintf(stderr,"vi.yoff = %d\n", vi->yoffset);
    fprintf(stderr, "vi.bits_per_pixel = %d\n", vi->bits_per_pixel);

    fprintf(stderr, "fi.line_length = %d\n", fi->line_length);

}

int gr_init(void)
{
    int fd = -1;

    if (!access("/dev/tty0", F_OK)) {
        fd = open("/dev/tty0", O_RDWR | O_SYNC);
        if(fd < 0)
            return -1;

        if(ioctl(fd, KDSETMODE, (void*) KD_GRAPHICS)) {
            close(fd);
            return -1;
        }
    }

    gr_fb_fd = get_framebuffer(gr_framebuffer);

    if(gr_fb_fd < 0) {
        if (fd >= 0) {
            ioctl(fd, KDSETMODE, (void*) KD_TEXT);
            close(fd);
        }
        return -1;
    }

    gr_vt_fd = fd;

        /* start with 0 as front (displayed) and 1 as back (drawing) */
    gr_active_fb = 0;
    set_active_framebuffer(0);

    return 0;
}

void gr_exit(void)
{
    close(gr_fb_fd);
    gr_fb_fd = -1;

    if (gr_vt_fd >= 0) {
        ioctl(gr_vt_fd, KDSETMODE, (void*) KD_TEXT);
        close(gr_vt_fd);
        gr_vt_fd = -1;
    }
}

int gr_fb_width(void)
{
    return gr_framebuffer[0].width;
}

int gr_fb_height(void)
{
    return gr_framebuffer[0].height;
}

uint16_t red = 0xf800;
uint16_t green = 0x07e0;
uint16_t blue = 0x001f;

void draw_grid(int w, int h, uint16_t* loc) {
  int i, j;
  int v;
  int stride = fi.line_length / (vi.bits_per_pixel >> 3);

  for (j = 0; j < h/2; j++) {
    for (i = 0; i < w/2; i++)
      loc[i + j*(stride)] = red;
    for (; i < w; i++)
      loc[i + j*(stride)] = green;
  }
  for (; j < h; j++) {
    for (i = 0; i < w/2; i++)
      loc[i + j*(stride)] = blue;
    for (; i < w; i++)
      loc[i + j*(stride)] = 0xffff;
  }

}

void clear_screen(int w, int h, uint16_t* loc)
{
    int i,j;
    int stride = fi.line_length / (vi.bits_per_pixel >> 3);

  for (j = 0; j < h; j++)
    for (i = 0; i < w; i++)
      loc[i + j*(stride)] = 0x0000;
}

int main(int argc, char **argv) {
  int w;
  int h;
  int id = 0;
  gr_init();
  w = vi.xres;
  h = vi.yres;
  clear_screen(w, h, (uint16_t *)gr_framebuffer[0].data);
  clear_screen(w, h, (uint16_t *)gr_framebuffer[1].data);

  if (argc > 2) {
    w = atoi(argv[1]);
    h = atoi(argv[2]);
  }

  if (argc > 3)
      id = !!atoi(argv[3]);

  draw_grid(w, h, (uint16_t *)gr_framebuffer[id].data);
  set_active_framebuffer(!id);
  set_active_framebuffer(id);

  return 0;
}
