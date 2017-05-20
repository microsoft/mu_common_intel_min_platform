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
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Guid/SmramMemoryReserve.h>

CHAR8 *mSmramStateName[] = {
  "Open",
  "Closed",
  "Locked",
  "Cacheable",
  "Allocated",
  "NeedTest",
  "NeedEccInit",
};

VOID
DumpSmramDescriptor (
  IN UINTN                 NumberOfSmmReservedRegions,
  IN EFI_SMRAM_DESCRIPTOR  *Descriptor
  )
{
  UINTN                                 Index;
  UINTN                                 BitIndex;

  for (Index = 0; Index < NumberOfSmmReservedRegions; Index++) {
    DEBUG ((DEBUG_INFO,
      "  BA=%016lx (A=%016lx) L=%016lx  State=%016lx",
      Descriptor[Index].PhysicalStart,
      Descriptor[Index].CpuStart,
      Descriptor[Index].PhysicalSize,
      Descriptor[Index].RegionState
      ));
    DEBUG ((DEBUG_INFO, "  ("));
    for (BitIndex = 0; BitIndex < sizeof(mSmramStateName)/sizeof(mSmramStateName[0]); BitIndex++) {
      if ((Descriptor[Index].RegionState & LShiftU64 (1, BitIndex)) != 0) {
        DEBUG ((DEBUG_INFO, mSmramStateName[BitIndex]));
        DEBUG ((DEBUG_INFO, ","));
      }
    }
    DEBUG ((DEBUG_INFO, ")\n"));
  }
}

EFI_STATUS
TestPointDumpSmramHob (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS                  Hob;
  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK        *SmramHobDescriptorBlock;
  BOOLEAN                               Found;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmramHob - Enter\n"));
  Hob.Raw = GetHobList ();
  DEBUG ((DEBUG_INFO, "SMRAM HOB\n"));
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == EFI_HOB_TYPE_GUID_EXTENSION) {
      if (CompareGuid (&Hob.Guid->Name, &gEfiSmmPeiSmramMemoryReserveGuid)) {
        SmramHobDescriptorBlock = (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *) (Hob.Guid + 1);
        DumpSmramDescriptor (SmramHobDescriptorBlock->NumberOfSmmReservedRegions, SmramHobDescriptorBlock->Descriptor);
        Found = TRUE;
        break;
      }
    }
    Hob.Raw = GET_NEXT_HOB (Hob);
  }
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmramHob - Exit\n"));

  if (!Found) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_CODE_3 TEST_POINT_MEMORY_DISCOVERED TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_STRING_3
      );
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}
