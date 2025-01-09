/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiPei.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MtrrLib.h>
#include "TestPointCheckMtrr.h" // MU_CHANGE

EFI_STATUS
TestPointCheckMtrrForPei (
  IN MTRR_SETTINGS  *Mtrrs,
  IN VARIABLE_MTRR  *VariableMtrr
  )
{
  EFI_STATUS                  Status;
  VOID                        *HobList;
  EFI_HOB_HANDOFF_INFO_TABLE  *PhitHob;
  
  HobList = GetHobList ();
  PhitHob = HobList;

  //
  // DRAM must be WB
  //
  DEBUG ((DEBUG_INFO, "MTRR Checking 0x%lx 0x%lx\n", PhitHob->EfiMemoryBottom, PhitHob->EfiMemoryTop - PhitHob->EfiMemoryBottom));
  Status = TestPointCheckCacheType (
             Mtrrs,
             VariableMtrr,
             PhitHob->EfiMemoryBottom,
             PhitHob->EfiMemoryTop - PhitHob->EfiMemoryBottom,
             CacheWriteBack
             );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // FV must be WB or WP
  //

  //
  // MMIO must be UC
  //

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointCheckMtrrForDxe (
  IN MTRR_SETTINGS  *Mtrrs,
  IN VARIABLE_MTRR  *VariableMtrr
  )
{
  EFI_STATUS                  Status;
  VOID                        *HobList;
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR *ResourceHob;
  
  HobList = GetHobList ();

  //
  // DRAM must be WB
  //
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      ResourceHob = Hob.ResourceDescriptor;
      switch (ResourceHob->ResourceType) {
      case EFI_RESOURCE_SYSTEM_MEMORY:
        if (((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) == TESTED_MEMORY_ATTRIBUTES) ||
            ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) == INITIALIZED_MEMORY_ATTRIBUTES)) {
          DEBUG ((DEBUG_INFO, "MTRR Checking 0x%lx 0x%lx\n", ResourceHob->PhysicalStart, ResourceHob->ResourceLength));
          Status = TestPointCheckCacheType (
                     Mtrrs,
                     VariableMtrr,
                     ResourceHob->PhysicalStart,
                     ResourceHob->ResourceLength,
                     CacheWriteBack
                     );
          if (EFI_ERROR(Status)) {
            return Status;
          }
        }
        break;
      default:
        break;
      }
    }
  }

  //
  // FV must be WB or WP
  //

  //
  // MMIO must be UC
  //

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointCheckMtrr (
  IN BOOLEAN   IsForDxe
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
    DEBUG ((DEBUG_INFO, "Variable MTRR[%02d]: Base=%016lx Mask=%016lx\n",
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
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  } else {

    ZeroMem (VariableMtrr, sizeof(VariableMtrr));
    TestPointMtrrConvert (Mtrrs, VariableMtrr);

    if (IsForDxe) {
      Status = TestPointCheckMtrrForDxe (Mtrrs, VariableMtrr);
    } else {
      Status = TestPointCheckMtrrForPei (Mtrrs, VariableMtrr);
    }
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    } else {
      Result = TRUE;
    }
  }

  if (!Result) {
    if (IsForDxe) {
      TestPointLibAppendErrorString (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI,
        TEST_POINT_BYTE2_END_OF_PEI_MTRR_FUNCTIONAL_ERROR_CODE \
          TEST_POINT_END_OF_PEI \
          TEST_POINT_BYTE2_END_OF_PEI_MTRR_FUNCTIONAL_ERROR_STRING
        );
    } else {
      TestPointLibAppendErrorString (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI,
        TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL_ERROR_CODE \
          TEST_POINT_MEMORY_DISCOVERED \
          TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL_ERROR_STRING
        );
    }
  }

  return Status;
}
