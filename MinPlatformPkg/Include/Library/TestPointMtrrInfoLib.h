/** @file
TestPointMtrrInfoLib.h

An interface for platforms to define the expected MTRR cache types for specific
regions.  Create an array of VARIABLE_MTRR_INFO structures for every MTRR range
that you want to validate.  If any of the checked regions don't have the matching
caching type the test will report an error for the failing range and return.

Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef TEST_POINT_MTRR_INFO_LIB_H_
#define TEST_POINT_MTRR_INFO_LIB_H_

#include <Uefi.h>

typedef struct {
  UINT64     BaseAddress;
  UINT64     Type;
} VARIABLE_MTRR_INFO;

typedef enum {
  EndOfDxe,
  ReadyToLock,
  ReadyToBoot,
  ExitBootServices,
  MaxBootPoint
} BOOT_POINT;

/**
  Assigns the input parameter pointer to a static array of VARIABLE_MTRR_INFO structures and returns
  the length of the array.

  @param[out]       CheckedMtrrs  Pointer to the head of an array of VARIABLE_MTRR_INFO structures.
                                  The caller shall not free this array.
  @param[in]        Boot          Enum value that represents the stage of boot which we want the comparisons
                                  to be made.

  @retval           UINTN         Length of the returned array.

**/
UINTN
EFIAPI
GetPlatformMtrrCacheData (
  OUT VARIABLE_MTRR_INFO **CheckedMtrrs,
  IN  BOOT_POINT         Boot
  );

#endif
