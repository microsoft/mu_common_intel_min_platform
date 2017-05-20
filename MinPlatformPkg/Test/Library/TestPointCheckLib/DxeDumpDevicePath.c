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
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

EFI_STATUS
TestPointDumpDevicePath (
  VOID
  )
{
  UINTN                             Index;
  EFI_HANDLE                        *HandleBuf;
  UINTN                             HandleCount;
  EFI_DEVICE_PATH_PROTOCOL          *DevicePath;
  EFI_STATUS                        Status;
  CHAR16                            *Str;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpDevicePath - Enter\n"));
  HandleBuf = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDevicePathProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuf
                  );
  if (EFI_ERROR (Status)) {
    goto Done ;
  }

  DEBUG ((DEBUG_INFO, "DeviceList:\n"));
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                  HandleBuf[Index],
                  &gEfiDevicePathProtocolGuid,
                  (VOID**)&DevicePath
                 );
    if (EFI_ERROR (Status)) {
      continue;
    }
    Str = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
    DEBUG ((DEBUG_INFO, "  %s\n", Str));
    if (Str != NULL) {
      FreePool (Str);
    }
  }

Done:
  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  DEBUG ((DEBUG_INFO, "==== TestPointDumpDevicePath - Enter\n"));

  // Check - TBD
  return EFI_SUCCESS;
}