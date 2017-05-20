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
#include <Library/TestPointCheckLib.h>
#include <Library/DebugLib.h>

VOID
TestPointDumpCpuInfo (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointTempMemoryInitDone (
  IN VOID   *TempRamStart,
  IN VOID   *TempRamEnd
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointTempMemoryInitDone - Enter\n"));

  DEBUG ((DEBUG_INFO, "TempRamStart - 0x%08x\n", TempRamStart));
  DEBUG ((DEBUG_INFO, "TempRamEnd   - 0x%08x\n", TempRamEnd));

  TestPointDumpCpuInfo ();

  DEBUG ((DEBUG_INFO, "======== TestPointTempMemoryInitDone - Exit\n"));

  return EFI_SUCCESS;
}
