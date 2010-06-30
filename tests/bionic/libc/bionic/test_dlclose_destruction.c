/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* this program is used to check that static C++ destructors are
 * properly called when dlclose() is called. We do this by using
 * a helper C++ shared library.
 *
 * See libdlclosetest1.cpp for details.
 */
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void*  lib = dlopen("libdlclosetest1.so", RTLD_NOW);
    int*   to_x;
    void  (*set_y)(int *);
    int    y = 0;

    if (lib == NULL) {
        fprintf(stderr, "Could not load shared library: %s\n", dlerror());
        return 1;
    }

    fprintf(stderr, "Loaded !!\n");

    to_x = dlsym(lib, "x");
    if (to_x == NULL) { 
        fprintf(stderr, "Could not access global DLL variable (x): %s\n", dlerror());
        return 10;
    }

    if (*to_x != 1) {
        fprintf(stderr, "Static C++ constructor was not run on dlopen() !\n");
        return 11;
    }

    set_y = dlsym(lib, "set_y");
    if (set_y == NULL) {
        fprintf(stderr, "Could not access global DLL function (set_y): %s\n", dlerror());
        return 12;
    }

    y = 0;
    (*set_y)(&y);

    if (dlclose(lib) < 0) {
        fprintf(stderr, "Could not unload shared library: %s\n", dlerror());
        return 2;
    }

    fprintf(stderr, "Unloaded !!\n");

    if (y != 2) {
        fprintf(stderr, "Static C++ destructor was not run on dlclose() !\n");
        return 11;
    }

    return 0;
}
