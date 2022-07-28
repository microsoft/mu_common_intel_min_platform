/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

BOOLEAN
IsRuntimeImage (
  IN VOID  *Pe32Data
  );

VOID
DumpLoadedImage (
  IN UINTN                      Index,
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  );
