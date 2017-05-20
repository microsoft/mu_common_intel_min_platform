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
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/SmmAccess2.h>

VOID
DumpSmramDescriptor (
  IN UINTN                 NumberOfSmmReservedRegions,
  IN EFI_SMRAM_DESCRIPTOR  *Descriptor
  );

VOID
DumpSmramInfo (
  VOID
  )
{
}

EFI_STATUS
TestPointDumpSmmInfo (
  VOID
  )
{
  EFI_STATUS               Status;
  EFI_SMM_ACCESS2_PROTOCOL *SmmAccess;
  UINTN                    Size;
  EFI_SMRAM_DESCRIPTOR     *SmramRanges;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmmInfo - Enter\n"));
  
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  if (EFI_ERROR (Status)) {
    goto Done ;
  }
  
  Size = 0;
  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, NULL);
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  SmramRanges = (EFI_SMRAM_DESCRIPTOR *) AllocateZeroPool (Size);
  ASSERT (SmramRanges != NULL);

  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, SmramRanges);
  ASSERT_EFI_ERROR (Status);
  
  DEBUG ((DEBUG_INFO, "SMRAM Info\n"));
  DumpSmramDescriptor (Size / sizeof (EFI_SMRAM_DESCRIPTOR), SmramRanges);

  FreePool (SmramRanges);

Done:
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmmInfo - Exit\n"));

  if (EFI_ERROR(Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_ERROR_CODE_1 TEST_POINT_DXE_SMM_READY_TO_LOCK TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_ERROR_STRING_1
      );
  }

  return Status;
}