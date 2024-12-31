/** @file
TestPointMtrrInfoLib.h

An interface for platforms to define the expected MTRR cache types for specific
regions by Ready To Boot.  Create an array of VARIABLE_MTRR_INFO structures for every
MTRR range that you want to validate.  If any of the checked regions don't have the
matching caching type the test will report an error for the failing range and return.

Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_POINT_MTRR_INFO_LIB_H_
#define _TEST_POINT_MTRR_INFO_LIB_H_

#include <Uefi.h>

typedef struct {
  UINT64     BaseAddress;
  UINT64     Type;
} VARIABLE_MTRR_INFO;

/**
  Assigns the input parameter pointer to a static array of VARIABLE_MTRR_INFO structures and returns
  the length of the array.

  @param[out]       CheckedMtrrs  Pointer to the head of an array of VARIABLE_MTRR_INFO structures.
                                  The caller shall not free this array.

  @retval           UINTN         Length of the returned array.

**/
UINTN
GetPlatformMtrrCacheData (
  OUT VARIABLE_MTRR_INFO **CheckedMtrrs
  );

#endif
