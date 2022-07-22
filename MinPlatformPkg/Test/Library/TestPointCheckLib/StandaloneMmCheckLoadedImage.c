/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2022, Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/StandaloneMmMemLib.h>
#include <Protocol/LoadedImage.h>

VOID
TestPointDumpStandaloneMmLoadedImage (
  VOID
  );

VOID
DumpLoadedImageInternal (
  IN UINTN                      Index,
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  );

VOID
DumpLoadedImage (
  IN UINTN                      Index,
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  )
{
  DumpLoadedImageInternal (Index, LoadedImage, DevicePath, LoadedImageDevicePath);
}

VOID
TestPointDumpStandaloneMmLoadedImage (
  VOID
  )
{
  TestPointDumpMmLoadedImage ();
}
