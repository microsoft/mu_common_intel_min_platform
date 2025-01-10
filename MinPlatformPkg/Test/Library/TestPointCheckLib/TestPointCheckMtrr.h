/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_POINT_CHECK_MTRR_H_
#define _TEST_POINT_CHECK_MTRR_H_

#include <Uefi.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MtrrLib.h>

#define MEMORY_ATTRIBUTE_MASK (EFI_RESOURCE_ATTRIBUTE_PRESENT | \
                               EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
                               EFI_RESOURCE_ATTRIBUTE_TESTED | \
                               EFI_RESOURCE_ATTRIBUTE_16_BIT_IO | \
                               EFI_RESOURCE_ATTRIBUTE_32_BIT_IO | \
                               EFI_RESOURCE_ATTRIBUTE_64_BIT_IO \
                               )

#define TESTED_MEMORY_ATTRIBUTES      (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED)

#define INITIALIZED_MEMORY_ATTRIBUTES (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED)

#define PRESENT_MEMORY_ATTRIBUTES     (EFI_RESOURCE_ATTRIBUTE_PRESENT)

MTRR_MEMORY_CACHE_TYPE
SetCurrentCacheType (
  IN MTRR_MEMORY_CACHE_TYPE  CurrentCacheType,
  IN MTRR_MEMORY_CACHE_TYPE  NewCacheType
  );

EFI_STATUS
TestPointCheckCacheType (
  IN MTRR_SETTINGS           *Mtrrs,
  IN VARIABLE_MTRR           *VariableMtrr,
  IN UINT64                  Base,
  IN UINT64                  Length,
  IN MTRR_MEMORY_CACHE_TYPE  ExpectedCacheType
  );

EFI_STATUS
TestPointCheckMtrrMask (
  IN MTRR_SETTINGS  *Mtrrs
  );

VOID
TestPointMtrrConvert (
  IN  MTRR_SETTINGS  *Mtrrs,
  OUT VARIABLE_MTRR  *VariableMtrr
  );

#endif
