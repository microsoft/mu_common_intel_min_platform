/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/MmServicesTableLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmMemoryAttributesTable.h>
#include <Protocol/LoadedImage.h>

VOID
TestPointDumpMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  );

EFI_STATUS
TestPointCheckImageMemoryAttribute (
  IN EFI_MEMORY_ATTRIBUTES_TABLE     *MemoryAttributesTable,
  IN EFI_PHYSICAL_ADDRESS            ImageBase,
  IN UINT64                          ImageSize,
  IN BOOLEAN                         IsFromMm
  );

EFI_STATUS
EFIAPI
MmGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  );


EFI_STATUS
TestPointCheckMmMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  )
{
  EFI_STATUS                             Status;
  EFI_LOADED_IMAGE_PROTOCOL              *LoadedImage;
  UINTN                                  Index;
  UINTN                                  HandleBufSize;
  EFI_HANDLE                             *HandleBuf;
  UINTN                                  HandleCount;
  EFI_STATUS                             ReturnStatus;
  
  ReturnStatus = EFI_SUCCESS;
  DEBUG ((DEBUG_INFO, "==== TestPointDumpMmLoadedImage - Enter\n"));
  HandleBuf = NULL;
  HandleBufSize = 0;
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    HandleBuf
                    );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    goto Done ;
  }
  HandleBuf = AllocateZeroPool (HandleBufSize);
  if (HandleBuf == NULL) {
    goto Done ;
  }
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    HandleBuf
                    );
  if (EFI_ERROR (Status)) {
    goto Done ;
  }
  HandleCount = HandleBufSize / sizeof(EFI_HANDLE);
  
  DEBUG ((DEBUG_INFO, "MmLoadedImage (%d):\n", HandleCount));
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gMmst->MmHandleProtocol (
                      HandleBuf[Index],
                      &gEfiLoadedImageProtocolGuid,
                      (VOID **)&LoadedImage
                      );
    if (EFI_ERROR(Status)) {
      continue;
    }
    Status = TestPointCheckImageMemoryAttribute (
               MemoryAttributesTable,
               (EFI_PHYSICAL_ADDRESS)(UINTN)LoadedImage->ImageBase,
               LoadedImage->ImageSize,
               TRUE
               );
    if (EFI_ERROR(Status)) {
      ReturnStatus = Status;
    }
  }

Done:

  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  return ReturnStatus;
}

EFI_STATUS
TestPointCheckMmMemAttribute (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *MemoryAttributesTable;
  
  DEBUG ((DEBUG_INFO, "==== TestPointCheckMmMemAttribute - Enter\n"));
  Status = MmGetSystemConfigurationTable (&gEdkiiPiSmmMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    TestPointDumpMemoryAttributesTable(MemoryAttributesTable);
    Status = TestPointCheckMmMemoryAttributesTable(MemoryAttributesTable);
  }

  if (EFI_ERROR (Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
      TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_CODE \
        TEST_POINT_SMM_READY_TO_LOCK \
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_STRING
      );
  }
  DEBUG ((DEBUG_INFO, "==== TestPointCheckMmMemAttribute - Exit\n"));

  return Status;
}
