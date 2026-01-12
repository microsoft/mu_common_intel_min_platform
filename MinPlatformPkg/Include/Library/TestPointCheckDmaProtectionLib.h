/** @file TestPointDmaProtectionLib.h

  Library to provide VTD related implementation for TestPointCheckLib

  Copyright (c) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef TEST_POINT_CHECK_DMA_PROTECTION_LIB_H_
#define TEST_POINT_CHECK_DMA_PROTECTION_LIB_H_

/**
  This function checks if DMA Remapping Hardware Unit Definitions
  described are configured properly. 

  @retval EFI_SUCCESS         DMA protection is supported.
  @retval other               DMA protection is nor supported.
**/
EFI_STATUS
EFIAPI
TestPointVtdEngine (
  VOID
  );

#endif
