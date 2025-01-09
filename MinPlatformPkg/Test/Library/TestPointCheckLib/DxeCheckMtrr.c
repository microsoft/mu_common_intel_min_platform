/** @file

Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MtrrLib.h>
#include <Library/TestPointMtrrInfoLib.h>
#include "TestPointCheckMtrr.h"

EFI_STATUS
TestPointCheckMtrrForDxe (
  IN MTRR_SETTINGS  *Mtrrs,
  IN VARIABLE_MTRR  *VariableMtrr
  )
{
  UINTN               VariableMtrrIndex;
  UINTN               VariableMtrrCount;
  VARIABLE_MTRR_INFO  *ExpectedMtrrs;
  UINTN               ExpectedMtrrsIndex;
  UINTN               ExpectedMtrrsCount;
  BOOLEAN             Found;

  ExpectedMtrrsCount = GetPlatformMtrrCacheData (&ExpectedMtrrs, ReadyToBoot);
  VariableMtrrCount  = GetVariableMtrrCount ();

  if ((ExpectedMtrrs == NULL) || (ExpectedMtrrsCount == 0)) {
    return EFI_NOT_FOUND;
  }

  //
  // Check if the MTRR types match
  //
  for (VariableMtrrIndex = 0; VariableMtrrIndex < VariableMtrrCount; VariableMtrrIndex++) {
    Found = FALSE;
    if (!VariableMtrr[VariableMtrrIndex].Valid) {
      continue;
    }

    for (ExpectedMtrrsIndex = 0; ExpectedMtrrsIndex < ExpectedMtrrsCount; ExpectedMtrrsIndex++) {
      if (ExpectedMtrrs[ExpectedMtrrsIndex].BaseAddress == VariableMtrr[VariableMtrrIndex].BaseAddress) {
        if (ExpectedMtrrs[ExpectedMtrrsIndex].Type != VariableMtrr[VariableMtrrIndex].Type) {
          DEBUG ((
            DEBUG_ERROR,
            "The Mtrr with BaseAddress: 0x%016lx has the incorrect cache type: %d!  Expected: %d\n",
            VariableMtrr[VariableMtrrIndex].BaseAddress,
            VariableMtrr[VariableMtrrIndex].Type,
            ExpectedMtrrs[ExpectedMtrrsIndex].Type
            ));
          return EFI_SECURITY_VIOLATION;
        }

        Found = TRUE;
        DEBUG ((DEBUG_INFO, "Found MTRR at address %016lx and it has the expected caching type\n", VariableMtrr[VariableMtrrIndex].BaseAddress));
        break;
      }
    }

    if (!Found) {
      DEBUG ((
        DEBUG_INFO,
        "The Mtrr with BaseAddress: 0x%016lx did not have a policy to check against.\n",
        VariableMtrr[VariableMtrrIndex].BaseAddress
        ));
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointCheckMtrr (
  VOID
  )
{
  EFI_STATUS     Status;
  MTRR_SETTINGS  LocalMtrrs;
  MTRR_SETTINGS  *Mtrrs;
  UINTN          Index;
  UINTN          VariableMtrrCount;
  BOOLEAN        Result;
  VARIABLE_MTRR  VariableMtrr[MTRR_NUMBER_OF_VARIABLE_MTRR];

  DEBUG ((DEBUG_INFO, "==== TestPointCheckMtrr - Enter\n"));

  MtrrGetAllMtrrs (&LocalMtrrs);
  Mtrrs = &LocalMtrrs;
  DEBUG ((DEBUG_INFO, "MTRR Default Type: %016lx\n", Mtrrs->MtrrDefType));
  for (Index = 0; Index < MTRR_NUMBER_OF_FIXED_MTRR; Index++) {
    DEBUG ((DEBUG_INFO, "Fixed MTRR[%02d]   : %016lx\n", Index, Mtrrs->Fixed.Mtrr[Index]));
  }

  VariableMtrrCount = GetVariableMtrrCount ();
  for (Index = 0; Index < VariableMtrrCount; Index++) {
    DEBUG ((
      DEBUG_INFO,
      "Variable MTRR[%02d]: Base=%016lx Mask=%016lx\n",
      Index,
      Mtrrs->Variables.Mtrr[Index].Base,
      Mtrrs->Variables.Mtrr[Index].Mask
      ));
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "==== TestPointCheckMtrr - Exit\n"));

  //
  // Check Mask
  //
  Status = TestPointCheckMtrrMask (Mtrrs);
  if (EFI_ERROR (Status)) {
    Result = FALSE;
  } else {
    ZeroMem (VariableMtrr, sizeof (VariableMtrr));
    TestPointMtrrConvert (Mtrrs, VariableMtrr);

    Status = TestPointCheckMtrrForDxe (Mtrrs, VariableMtrr);

    if (EFI_ERROR (Status)) {
      Result = FALSE;
    } else {
      Result = TRUE;
    }
  }

  // Print error string if we failed
  if (!Result) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI,
      TEST_POINT_BYTE4_READY_TO_BOOT_MTRR_CACHE_VALID_ERROR_CODE \
      TEST_POINT_READY_TO_BOOT \
      TEST_POINT_BYTE4_READY_TO_BOOT_MTRR_CACHE_VALID_ERROR_STRING
      );
  }

  return Status;
}
