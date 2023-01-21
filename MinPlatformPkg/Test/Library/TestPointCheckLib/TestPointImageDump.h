/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_POINT_IMAGE_DUMP_H_
#define _TEST_POINT_IMAGE_DUMP_H_

#include <Uefi.h>
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

EFI_STATUS
TestPointCheckNon3rdPartyImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  );

#endif
