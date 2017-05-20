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
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>

CHAR16  *mConsoleVariableList[] = {
  L"ConIn",
  L"ConInDev",
  L"ConOut",
  L"ConOutDev",
  L"ErrOut",
  L"ErrOutDev",
};

VOID
DumpDevicePath (
  IN CHAR16           *Name,
  IN EFI_DEVICE_PATH  *DevicePath,
  IN UINTN            Size
  )
{
  CHAR16 *Str;

  Str = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
  DEBUG ((DEBUG_INFO, "%s: %s\n", Name, Str));
  if (Str != NULL) {
    FreePool (Str);
  }
}

EFI_STATUS
TestPointDumpConsoleVariable (
  VOID
  )
{
  VOID        *Variable;
  UINTN       Size;
  UINTN       Index;
  EFI_STATUS  Status;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpConsoleVariable - Enter\n"));
  for (Index = 0; Index < sizeof(mConsoleVariableList)/sizeof(mConsoleVariableList[0]); Index++) {
    Status = GetVariable2 (mConsoleVariableList[Index], &gEfiGlobalVariableGuid, &Variable, &Size);
    if (!EFI_ERROR(Status)) {
      DumpDevicePath (mConsoleVariableList[Index], Variable, Size);
    }
  }
  DEBUG ((DEBUG_INFO, "==== TestPointDumpConsoleVariable - Exit\n"));

  // Check - TBD
  return EFI_SUCCESS;
}
