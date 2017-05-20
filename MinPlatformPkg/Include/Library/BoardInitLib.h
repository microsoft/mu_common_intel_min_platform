/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _BOARD_INIT_LIB_H_
#define _BOARD_INIT_LIB_H_

#include <PiPei.h>
#include <Uefi.h>

EFI_STATUS
EFIAPI
BoardDetect (
  VOID
  );

EFI_STATUS
EFIAPI
BoardDebugInit (
  VOID
  );

EFI_BOOT_MODE
EFIAPI
BoardBootModeDetect (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitBeforeMemoryInit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitAfterMemoryInit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitBeforeTempRamExit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitAfterTempRamExit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitBeforeSiliconInit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitAfterSiliconInit (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitAfterPciEnumeration (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitReadyToBoot (
  VOID
  );

EFI_STATUS
EFIAPI
BoardInitEndOfFirmware (
  VOID
  );

#endif
