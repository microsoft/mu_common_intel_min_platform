/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2022, Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

VOID
DumpLoadedImage (
  IN UINTN                                  Index,
  IN EFI_LOADED_IMAGE_PROTOCOL              *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL               *DevicePath,
  IN EFI_DEVICE_PATH_PROTOCOL               *LoadedImageDevicePath
  );

VOID
TestPointDumpMmLoadedImage (
  VOID
  )
{
  EFI_STATUS                 Status;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  UINTN                      Index;
  UINTN                      HandleBufSize;
  EFI_HANDLE                 *HandleBuf;
  UINTN                      HandleCount;
  EFI_DEVICE_PATH_PROTOCOL   *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath;

  DEBUG ((DEBUG_INFO, "==== TestPointDumpMmLoadedImage - Enter\n"));
  HandleBuf     = NULL;
  HandleBufSize = 0;
  Status        = gMmst->MmLocateHandle (
                           ByProtocol,
                           &gEfiLoadedImageProtocolGuid,
                           NULL,
                           &HandleBufSize,
                           HandleBuf
                           );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    goto Done;
  }

  HandleBuf = AllocateZeroPool (HandleBufSize);
  if (HandleBuf == NULL) {
    goto Done;
  }

  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    HandleBuf
                    );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  HandleCount = HandleBufSize / sizeof (EFI_HANDLE);

  DEBUG ((DEBUG_INFO, "MmLoadedImage (%d):\n", HandleCount));
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gMmst->MmHandleProtocol (
                      HandleBuf[Index],
                      &gEfiLoadedImageProtocolGuid,
                      (VOID **)&LoadedImage
                      );
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = gMmst->MmHandleProtocol (LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID **)&DevicePath);
    if (EFI_ERROR (Status)) {
      DevicePath = NULL;
    }

    DevicePath = NULL;

    Status = gMmst->MmHandleProtocol (HandleBuf[Index], &gEfiLoadedImageDevicePathProtocolGuid, (VOID **)&LoadedImageDevicePath);
    if (EFI_ERROR (Status)) {
      LoadedImageDevicePath = NULL;
    }

    DumpLoadedImage (Index, LoadedImage, DevicePath, LoadedImageDevicePath);
  }

Done:

  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  DEBUG ((DEBUG_INFO, "==== TestPointDumpMmLoadedImage - Exit\n"));

  return;
}
