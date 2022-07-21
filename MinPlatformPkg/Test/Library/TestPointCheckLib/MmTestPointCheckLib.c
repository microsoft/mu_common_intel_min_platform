/** @file

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h> 
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Guid/MemoryAttributesTable.h>

#include "TestPointInternal.h"

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GUID  mTestPointSmmCommunciationGuid = TEST_POINT_SMM_COMMUNICATION_GUID;

EFI_STATUS
TestPointCheckSmrr (
  VOID
  );

VOID
TestPointDumpMmLoadedImage (
  VOID
  );

EFI_STATUS
TestPointCheckMmMemAttribute (
  VOID
  );

EFI_STATUS
TestPointCheckMmPaging (
  VOID
  );

EFI_STATUS
TestPointCheckMmCommunicationBuffer (
  IN EFI_MEMORY_DESCRIPTOR        *UefiMemoryMap,
  IN UINTN                        UefiMemoryMapSize,
  IN UINTN                        UefiDescriptorSize,
  IN EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable
  );

/**
  This service verifies SMRR configuration at the End of DXE.

  Test subject: SMRR.
  Test overview: Verify SMRR is aligned and SMRR matches SMRAM_INFO.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps SMRR and SMRAM_INFO.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointMmEndOfDxeSmrrFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointMmEndOfDxeSmrrFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckSmrr ();
  if (EFI_ERROR (Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_INDEX_BYTE6_SMM,
      TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmEndOfDxe - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the security of MM communication buffers at MM Ready To Lock.

  Test subject: MM communication buffer.
  Test overview: Verify only CommBuffer and MMIO are mapped in the page table.
  Reporting mechanism: Dumps the memory map and GCD map at MmReadyToLock and checks at MmReadyToBoot.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointMmReadyToLockSecureMmCommunicationBuffer (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToLockSecureMmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //
  // Previous memory collection is allowed in MM but leaving this function for possible future collection

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToLockSecureMmCommunicationBuffer - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the system state within SMM after Exit Boot Services is invoked.

  @retval EFI_SUCCESS         The test point check was performed successfully.
**/
EFI_STATUS
EFIAPI
TestPointMmExitBootServices (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointMmExitBootServices - Enter\n"));

  DEBUG ((DEBUG_INFO, "======== TestPointMmExitBootServices - Exit\n"));
  return EFI_SUCCESS;
}
