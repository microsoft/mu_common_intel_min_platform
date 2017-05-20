/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <PiPei.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/MtrrLib.h>

EFI_STATUS
TestPointDumpMtrr (
  IN BOOLEAN   IsForDxe
  )
{
  MTRR_SETTINGS  LocalMtrrs;
  MTRR_SETTINGS  *Mtrrs;
  UINTN          Index;
  UINTN          VariableMtrrCount;
  BOOLEAN        Result;

  DEBUG ((DEBUG_INFO, "==== TestPointDumpMtrr - Enter\n"));

  MtrrGetAllMtrrs (&LocalMtrrs);
  Mtrrs = &LocalMtrrs;
  DEBUG ((DEBUG_INFO, "MTRR Default Type: %016lx\n", Mtrrs->MtrrDefType));
  for (Index = 0; Index < MTRR_NUMBER_OF_FIXED_MTRR; Index++) {
    DEBUG ((DEBUG_INFO, "Fixed MTRR[%02d]   : %016lx\n", Index, Mtrrs->Fixed.Mtrr[Index]));
  }

  VariableMtrrCount = GetVariableMtrrCount ();
  for (Index = 0; Index < VariableMtrrCount; Index++) {
    DEBUG ((DEBUG_INFO, "Variable MTRR[%02d]: Base=%016lx Mask=%016lx\n",
      Index,
      Mtrrs->Variables.Mtrr[Index].Base,
      Mtrrs->Variables.Mtrr[Index].Mask
      ));
  }
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "==== TestPointDumpMtrr - Exit\n"));

  // Check - TBD
  if (IsForDxe) {
    Result = TRUE;
  } else {
    Result = TRUE;
  }

  if (!Result) {
    if (IsForDxe) {
      TestPointLibAppendErrorString (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_CODE_2 TEST_POINT_END_OF_PEI TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_STRING_2
        );
    } else {
      TestPointLibAppendErrorString (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_REFERENCE,
        NULL,
        TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_2 TEST_POINT_MEMORY_DISCOVERED TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_2
        );
    }
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}
