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
#include <Library/PeiServicesLib.h>
#include <Ppi/FirmwareVolumeInfo.h>
#include <Ppi/FirmwareVolumeInfo2.h>

EFI_STATUS
TestPointDumpFvInfo (
  VOID
  )
{
  EFI_STATUS                         Status;
  EFI_PEI_PPI_DESCRIPTOR             *Descriptor;
  EFI_PEI_FIRMWARE_VOLUME_INFO_PPI   *FvInfo;
  EFI_PEI_FIRMWARE_VOLUME_INFO2_PPI  *FvInfo2;
  UINTN                              Index;
  UINTN                              Index2;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpFvInfo - Enter\n"));
  DEBUG ((DEBUG_INFO, "FV Info PPI\n"));
  for (Index = 0; ; Index++) {
    Status = PeiServicesLocatePpi (
               &gEfiPeiFirmwareVolumeInfoPpiGuid,
               Index,
               &Descriptor,
               (VOID **)&FvInfo
               );
    if (EFI_ERROR (Status)) {
      break;
    }
    DEBUG ((DEBUG_INFO,
      "  BA=%08x  L=%08x  Format={%g}",
      (UINT32)(UINTN)FvInfo->FvInfo,
      FvInfo->FvInfoSize,
      &FvInfo->FvFormat,
      FvInfo->ParentFvName,
      FvInfo->ParentFileName
      ));
    if (FvInfo->ParentFvName != NULL) {
      DEBUG ((DEBUG_INFO,
        "  ParentFv={%g}",
        FvInfo->ParentFvName
        ));
    }
    if (FvInfo->ParentFileName != NULL) {
      DEBUG ((DEBUG_INFO,
        "  ParentFileName={%g}",
        FvInfo->ParentFileName
        ));
    }
    DEBUG ((DEBUG_INFO, "\n"));
  }
  
  DEBUG ((DEBUG_INFO, "FV Info2 PPI\n"));
  for (Index2 = 0; ; Index2++) {
    Status = PeiServicesLocatePpi (
               &gEfiPeiFirmwareVolumeInfo2PpiGuid,
               Index2,
               &Descriptor,
               (VOID **)&FvInfo2
               );
    if (EFI_ERROR (Status)) {
      break;
    }
    DEBUG ((DEBUG_INFO,
      "  BA=%08x  L=%08x  Format={%g}",
      (UINT32)(UINTN)FvInfo2->FvInfo,
      FvInfo2->FvInfoSize,
      &FvInfo2->FvFormat,
      FvInfo2->ParentFvName,
      FvInfo2->ParentFileName,
      FvInfo2->AuthenticationStatus
      ));
    if (FvInfo2->ParentFvName != NULL) {
      DEBUG ((DEBUG_INFO,
        "  ParentFv={%g}",
        FvInfo2->ParentFvName
        ));
    }
    if (FvInfo2->ParentFileName != NULL) {
      DEBUG ((DEBUG_INFO,
        "  ParentFileName={%g}",
        FvInfo2->ParentFileName
        ));
    }
    DEBUG ((DEBUG_INFO,
      "  Auth=%08x\n",
      FvInfo2->AuthenticationStatus
      ));
  }
  DEBUG ((DEBUG_INFO, "==== TestPointDumpFvInfo - Exit\n"));

  if ((Index == 0) && (Index2 == 0)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_3 TEST_POINT_END_OF_PEI TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_3
      );
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}
