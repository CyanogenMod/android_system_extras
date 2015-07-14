/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SIMPLE_PERF_PERF_REGS_H_
#define SIMPLE_PERF_PERF_REGS_H_

#include <asm-x86/asm/perf_regs.h>
#include <asm-arm/asm/perf_regs.h>
#define perf_event_arm_regs perf_event_arm64_regs
#include <asm-arm64/asm/perf_regs.h>
#include <stdint.h>
#include <string>

enum ArchType {
  ARCH_X86_32,
  ARCH_X86_64,
  ARCH_ARM,
  ARCH_ARM64,
};

ArchType GetCurrentArch();
bool SetCurrentArch(const std::string& arch);

uint64_t GetSupportedRegMask();

std::string GetRegName(size_t reg);

#endif  // SIMPLE_PERF_PERF_REGS_H_
