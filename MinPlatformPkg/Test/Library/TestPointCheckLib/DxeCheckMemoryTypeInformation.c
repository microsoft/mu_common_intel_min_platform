/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>

#include <Guid/MemoryTypeInformation.h>

CHAR8 *
ShortNameOfMemoryType (
  IN UINT32 Type
  );

//MU_CHANGE - Add minimum memory type allocations
/**
  This routine returns the minimum allocation for the given memory type.

  @param MemoryTypeMinimumAllocationInformation   Minimum allocations. May be NULL.
  @param Type                                     MemoryType to get the minimum allocation for.

  @return The minimum allocation (in pages) for this memory type, or 0 if
          no minimum is provided.
**/
UINT32
GetMinimumAllocation (
  IN CONST EFI_MEMORY_TYPE_INFORMATION  *MemoryTypeMinimumAllocationInformation,
  IN UINT32                             Type
  )
{
  UINTN   Index;
  UINT32  MinAllocation;

  if (MemoryTypeMinimumAllocationInformation == NULL) {
    return 0;
  }

  MinAllocation = 0;
  for (Index = 0; MemoryTypeMinimumAllocationInformation[Index].Type != EfiMaxMemoryType; Index++) {
    if (MemoryTypeMinimumAllocationInformation[Index].Type == Type) {
      break;
    }
  }

  if (MemoryTypeMinimumAllocationInformation[Index].Type == EfiMaxMemoryType) {
    MinAllocation = 0;
  } else {
    MinAllocation = MemoryTypeMinimumAllocationInformation[Index].NumberOfPages;
  }

  return MinAllocation;
}
//MU_CHANGE - END

/**
  Dump Memory Type Info Summary for debug.

  @param CurrentMemoryTypeInformation             Allocations by memory type for this boot.
  @param PreviousMemoryTypeInformation            Allocations by memory type for previous boot.
  @param MemoryTypeMinimumAllocationInformation   Minimum allocations. May be NULL.

**/
VOID
DumpMemoryTypeInfoSummary (
  IN CONST EFI_MEMORY_TYPE_INFORMATION  *CurrentMemoryTypeInformation,
  IN CONST EFI_MEMORY_TYPE_INFORMATION  *PreviousMemoryTypeInformation,
  IN CONST EFI_MEMORY_TYPE_INFORMATION  *MemoryTypeMinimumAllocationInformation //MU_CHANGE - Add minimum memory type allocations
  )
{
  UINTN          Index;
  UINTN          Index1;
  EFI_BOOT_MODE  BootMode;
  UINT32         Previous;
  UINT32         Current;
  UINT32         Next;
  UINT32         Minimum;  //MU_CHANGE - Add minimum memory type allocations
  BOOLEAN        MemoryTypeInformationModified;

  MemoryTypeInformationModified = FALSE;
  BootMode = GetBootModeHob ();

  //
  // Use a heuristic to adjust the Memory Type Information for the next boot
  //
  //MU_CHANGE - Add minimum memory type allocations
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "             (HOB)   (ConfTabl)   (HOB)    (Var)  \n"));
  DEBUG ((DEBUG_INFO, "  Memory    Previous  Current    Minimum   Next   \n"));
  DEBUG ((DEBUG_INFO, "   Type      Pages     Pages      Pages    Pages  \n"));
  DEBUG ((DEBUG_INFO, "==========  ========  ========  ========  ========\n"));
  //MU_CHANGE - END
  for (Index = 0; PreviousMemoryTypeInformation[Index].Type != EfiMaxMemoryType; Index++) {
    for (Index1 = 0; CurrentMemoryTypeInformation[Index1].Type != EfiMaxMemoryType; Index1++) {
      if (PreviousMemoryTypeInformation[Index].Type == CurrentMemoryTypeInformation[Index1].Type) {
        break;
      }
    }

    if (CurrentMemoryTypeInformation[Index1].Type == EfiMaxMemoryType) {
      continue;
    }

    //
    // Previous is the number of pages pre-allocated
    // Current is the number of pages actually needed
    //
    Previous = PreviousMemoryTypeInformation[Index].NumberOfPages;
    Current  = CurrentMemoryTypeInformation[Index1].NumberOfPages;
    //MU_CHANGE - Add minimum memory type allocations
    Minimum  = GetMinimumAllocation (MemoryTypeMinimumAllocationInformation, PreviousMemoryTypeInformation[Index].Type);
    Next     = Previous;
    //MU_CHANGE - End

    //
    // Inconsistent Memory Reserved across bootings may lead to S4 fail
    // Write next variable to 125% * current when the pre-allocated memory is:
    //  1. More than 150% of needed memory and boot mode is BOOT_WITH_DEFAULT_SETTING
    //  2. Less than the needed memory
    //
    if ((Current + (Current >> 1)) < Previous) {
      if (BootMode == BOOT_WITH_DEFAULT_SETTINGS) {
        Next = Current + (Current >> 2);
      }
    } else if (Current > Previous) {
      Next = Current + (Current >> 2);
    }

    if ((Next > 0) && (Next < 4)) {
      Next = 4;
    }
    //MU_CHANGE - Add minimum memory type allocations
    if (Next < Minimum) {
      Next = Minimum;
    }
    //MU_CHANGE - End
    if (Next != Previous) {
      MemoryTypeInformationModified = TRUE;
    }

    DEBUG ((DEBUG_INFO, ShortNameOfMemoryType (PreviousMemoryTypeInformation[Index].Type)));
    //MU_CHANGE - Add minimum memory type allocations
    DEBUG ((DEBUG_INFO, "  %08x  %08x  %08x  %08x\n", Previous, Current, Minimum, Next));
    //MU_CHANGE - End
  }

  DEBUG ((DEBUG_INFO, "\n"));

  if (MemoryTypeInformationModified) {
    DEBUG ((DEBUG_INFO, "MemoryTypeInformation - Modified. RESET Needed!\n"));
  } else {
    DEBUG ((DEBUG_INFO, "MemoryTypeInformation - Unmodified.\n"));
  }

  DEBUG ((DEBUG_INFO, "\n"));
}

EFI_STATUS
TestPointCheckMemoryTypeInformation (
  VOID
  )
{
  EFI_STATUS         Status;
  EFI_HOB_GUID_TYPE  *GuidHob;
  VOID               *CurrentMemoryTypeInformation;
  VOID               *PreviousMemoryTypeInformation;
  VOID               *MemoryTypeMinimumAllocationInformation; //MU_CHANGE - Add minimum memory type allocations

  DEBUG ((DEBUG_INFO, "==== TestPointCheckMemoryTypeInformation - Enter\n"));
  CurrentMemoryTypeInformation           = NULL;
  PreviousMemoryTypeInformation          = NULL;
  MemoryTypeMinimumAllocationInformation = NULL; //MU_CHANGE - Add minimum memory type allocations

  Status = EfiGetSystemConfigurationTable (&gEfiMemoryTypeInformationGuid, &CurrentMemoryTypeInformation);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  GuidHob = GetFirstGuidHob (&gEfiMemoryTypeInformationGuid);
  if (GuidHob != NULL) {
    PreviousMemoryTypeInformation = GET_GUID_HOB_DATA (GuidHob);
  } else {
    Status = EFI_NOT_FOUND;
    goto Done;
  }
  
  //MU_CHANGE - Add minimum memory type allocations
  GuidHob = GetFirstGuidHob (&gEfiMemoryTypeMinimumAllocationGuid);
  if (GuidHob != NULL) {
    MemoryTypeMinimumAllocationInformation = GET_GUID_HOB_DATA (GuidHob);
  }

  if ((CurrentMemoryTypeInformation != NULL) && (PreviousMemoryTypeInformation != NULL)) {
    DumpMemoryTypeInfoSummary (CurrentMemoryTypeInformation, PreviousMemoryTypeInformation, MemoryTypeMinimumAllocationInformation);
  }
  //MU_CHANGE - End

  DEBUG ((DEBUG_INFO, "==== TestPointCheckMemoryTypeInformation - Exit\n"));

Done:
  if (EFI_ERROR (Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
      TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL_ERROR_CODE \
      TEST_POINT_READY_TO_BOOT \
      TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL_ERROR_STRING
      );
  }

  return Status;
}
