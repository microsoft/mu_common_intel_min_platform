/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

VOID
TestPointDumpTraditionalMmLoadedImage (
  VOID
  )
{
  TestPointDumpMmLoadedImage ();
}
