/** @file TestPointCheckDmaProtectionLibNull.c

  NULL instance of TestPointCheckDmaProtectionLib Library.

  Copyright (c) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi/UefiBaseType.h>

/**
  This service checks if VTD DMA protection is supported.

  @retval EFI_UNSUPPORTED   Always return EFI_UNSUPPORTED since this is a null implementation.
**/
EFI_STATUS
EFIAPI
TestPointVtdEngine (
  VOID
  ) {
  return EFI_UNSUPPORTED;
}
