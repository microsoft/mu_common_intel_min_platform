/** @file
This file contains all the testpoint checks for MM.  Traditional or
Standalone MM exclusive checks are abstracted away as necessary but
are called from here.

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
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
#include "TestPointMm.h"

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GUID  mTestPointSmmCommunicationGuid = TEST_POINT_SMM_COMMUNICATION_GUID;

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mFeatureImplemented[TEST_POINT_FEATURE_SIZE];

GLOBAL_REMOVE_IF_UNREFERENCED ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  mTestPointStruct = {
  PLATFORM_TEST_POINT_VERSION,
  PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
  {TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM},
  TEST_POINT_FEATURE_SIZE,
  {0}, // FeaturesImplemented
  {0}, // FeaturesVerified
  0,
};

EFI_STATUS
TestPointCheckSmrr (
  VOID
  );

EFI_STATUS
TestPointCheckMmMemAttribute (
  VOID
  );

/**
  This service verifies the validity of the SMM page table at SMM Ready To Boot.
  Test subject: SMM page table.
  Test overview: Verify the SMM page table matches the SMM memory attribute table.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Reports an error message upon checking.
  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointMmReadyToBootMmPageProtection (
  VOID
  )
{
  EFI_STATUS Status;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM]
    & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToBootMmPageProtection - Enter\n"));
  Status = TestPointReadyToBootMmPageProtection ();
  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToBootMmPageProtection - Enter\n"));
  return Status;
}

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

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmEndOfDxeSmrrFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckSmrr ();
  if (EFI_ERROR (Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
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
  EFI_STATUS Status;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToLockSecureMmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //

  Status = TestPointReadyToLockSecureMmCommunicationBuffer ();

  // Previous memory collection is allowed in MM but leaving this function for possible future collection

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToLockSecureMmCommunicationBuffer - Exit\n"));
  return Status;
}

/**
  This service verifies the validity of the SMM memory attribute table at MM Ready To Lock.
  Test subject: MM memory attribute table.
  Test overview: Verify the MM memory attribute table is reported.
                 Verify image code/data is consistent with the SMM memory attribute table.
                 Verify the GDT/IDT/PageTable is RO, data is NX, and code is RO.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the MM memory attribute table and SMM image information.
  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointMmReadyToLockMmMemoryAttributeTableFunctional (
  VOID
  )
{
  EFI_STATUS Status;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] &
    TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  Status = TestPointReadyToLockMmMemoryAttributeTableFunctional ();
  return Status;
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

/**
  Dispatch function for a Software MMI handler.
  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-SMM environment into an SMM environment.
  @param CommBufferSize  The size of the CommBuffer.
  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
TestPointMmReadyToBootMmPageProtectionHandler (
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS Status;
  
  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM]
    & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  Status = TestPointReadyToBootMmPageProtectionHandler (CommBuffer, CommBufferSize);
  return Status;
}

/**
  Dispatch function for a Software MMI handler.
  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.
  @param DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param Context         Points to an optional handler context which was specified when the
                         handler was registered.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-SMM environment into an SMM environment.
  @param CommBufferSize  The size of the CommBuffer.
  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
EFIAPI
TestPointMmHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  TEST_POINT_SMM_COMMUNICATION_HEADER      CommData;
  UINTN                                    TempCommBufferSize;

  //
  // If input is invalid, stop processing this SMI
  //
  if (CommBuffer == NULL || CommBufferSize == NULL) {
    return EFI_SUCCESS;
  }

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize < sizeof(TEST_POINT_SMM_COMMUNICATION_HEADER)) {
    DEBUG((DEBUG_ERROR, "TestPointMmHandler: MM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }
  CopyMem (&CommData, CommBuffer, sizeof(CommData));
  if (CommData.Version != TEST_POINT_SMM_COMMUNICATION_VERSION) {
    DEBUG((DEBUG_ERROR, "TestPointMmHandler: MM communication Version invalid!\n"));
    return EFI_SUCCESS;
  }
  switch (CommData.FuncId) {
  case TEST_POINT_SMM_COMMUNICATION_FUNC_ID_UEFI_GCD_MAP_INFO:
    return TestPointMmReadyToBootMmPageProtectionHandler (CommBuffer, CommBufferSize);
  }
  return EFI_SUCCESS;
}

/**
  Register MM Test Point handler.
**/
VOID
RegisterMmTestPointHandler (
  VOID
  )
{
  EFI_STATUS    Status;
  EFI_HANDLE    DispatchHandle;

  Status = gMmst->MmiHandlerRegister (
                    TestPointMmHandler,
                    &mTestPointSmmCommunicationGuid,
                    &DispatchHandle
                    );
  ASSERT_EFI_ERROR (Status);
}

/**
  Initialize feature data.
  @param[in]  Role    The test point role being requested.
**/
VOID
InitData (
  IN UINT32                   Role
  )
{
  EFI_STATUS                             Status;

  ASSERT (PcdGetSize(PcdTestPointIbvPlatformFeature) == sizeof(mFeatureImplemented));
  CopyMem (mFeatureImplemented, PcdGetPtr(PcdTestPointIbvPlatformFeature), sizeof(mFeatureImplemented));

  mTestPointStruct.Role = Role;
  CopyMem (mTestPointStruct.FeaturesImplemented, mFeatureImplemented, sizeof(mFeatureImplemented));
  Status = TestPointLibSetTable (
             &mTestPointStruct,
             sizeof(mTestPointStruct)
             );
  if (EFI_ERROR (Status)) {
    if (Status != EFI_ALREADY_STARTED) {
      ASSERT_EFI_ERROR (Status);
    }
  }
}

/**
  The MM library constructor.
  The function does the necessary initialization work for this library
  instance.
  @retval     EFI_SUCCESS       The function always return EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
MmTestPointCheckLibConstructor (
  VOID
  )
{
  InitData (PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV);

  RegisterMmTestPointHandler ();

  return EFI_SUCCESS;
}
