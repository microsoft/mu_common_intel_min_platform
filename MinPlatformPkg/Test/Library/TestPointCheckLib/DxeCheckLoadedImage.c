/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Protocol/LoadedImage.h>

#include "TestPointImageDump.h"

EFI_STATUS
TestPointCheckLoadedImage (
  VOID
  )
{
  EFI_STATUS                             Status;
  EFI_LOADED_IMAGE_PROTOCOL              *LoadedImage;
  UINTN                                  Index;
  EFI_HANDLE                             *HandleBuf;
  UINTN                                  HandleCount;
  EFI_DEVICE_PATH_PROTOCOL               *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL               *LoadedImageDevicePath;
  EFI_STATUS                             ReturnStatus;
  
  ReturnStatus = EFI_SUCCESS;
  DEBUG ((DEBUG_INFO, "==== TestPointCheckLoadedImage - Enter\n"));
  HandleBuf = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiLoadedImageProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuf
                  );
  if (EFI_ERROR (Status)) {
    goto Done ;
  }
  
  DEBUG ((DEBUG_INFO, "LoadedImage (%d):\n", HandleCount));
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuf[Index],
                    &gEfiLoadedImageProtocolGuid,
                    (VOID **)&LoadedImage
                    );
    if (EFI_ERROR(Status)) {
      continue;
    }

    Status = gBS->HandleProtocol (LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID **)&DevicePath);
    if (EFI_ERROR(Status)) {
      DevicePath = NULL;
    }

    Status = gBS->HandleProtocol (HandleBuf[Index], &gEfiLoadedImageDevicePathProtocolGuid, (VOID **)&LoadedImageDevicePath);
    if (EFI_ERROR(Status)) {
      LoadedImageDevicePath = NULL;
    }

    DumpLoadedImage (Index, LoadedImage, DevicePath, LoadedImageDevicePath);

    Status = TestPointCheckNon3rdPartyImage (LoadedImage, DevicePath, LoadedImageDevicePath);
    if (EFI_ERROR(Status)) {
      ReturnStatus = Status;
      DEBUG ((DEBUG_ERROR, "3rd Party Image found - Index (%d)\n", Index));
      TestPointLibAppendErrorString (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
        TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM_ERROR_CODE \
          TEST_POINT_END_OF_DXE \
          TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM_ERROR_STRING
        );
    }
  }

Done:

  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  DEBUG ((DEBUG_INFO, "==== TestPointCheckLoadedImage - Exit\n"));

  return ReturnStatus;
}
