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
#include <Library/StandaloneMmMemLib.h>
#include <Library/MmServicesTableLib.h>
#include <Guid/MemoryAttributesTable.h>

#include "TestPointInternal.h"

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GUID mTestPointSmmCommunciationGuid = TEST_POINT_SMM_COMMUNICATION_GUID;

EFI_STATUS
TestPointCheckSmrr (
  VOID
  );

EFI_STATUS
TestPointDumpStandaloneMmLoadedImage (
  VOID
  );

EFI_STATUS
TestPointCheckStandaloneMmMemAttribute (
  VOID
  );

EFI_STATUS
TestPointCheckStandaloneMmPaging (
  VOID
  );

EFI_STATUS
TestPointCheckStandaloneMmCommunicationBuffer (
  IN EFI_MEMORY_DESCRIPTOR        *UefiMemoryMap,
  IN UINTN                        UefiMemoryMapSize,
  IN UINTN                        UefiDescriptorSize,
  IN EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable
  );

GLOBAL_REMOVE_IF_UNREFERENCED EFI_MEMORY_DESCRIPTOR *mUefiMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiMemoryMapSize;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiDescriptorSize;

EFI_MEMORY_ATTRIBUTES_TABLE  *mUefiMemoryAttributesTable;

GLOBAL_REMOVE_IF_UNREFERENCED ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  mTestPointStruct = {
  PLATFORM_TEST_POINT_VERSION,
  PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
  {TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM},
  TEST_POINT_FEATURE_SIZE,
  {0}, // FeaturesImplemented
  {0}, // FeaturesVerified
  0,
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mFeatureImplemented[TEST_POINT_FEATURE_SIZE];

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
TestPointStandaloneMmEndOfDxeSmrrFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }
  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmEndOfDxeSmrrFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckSmrr ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      5,
      TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmEndOfDxe - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the security of Standalone MM communication buffers at Standalone MM Ready To Lock.

  Test subject: Standalone MM communication buffer.
  Test overview: Verify only CommBuffer and MMIO are mapped in the page table.
  Reporting mechanism: Dumps the memory map and GCD map at StandaloneMmReadyToLock and checks at StandaloneMmReadyToBoot.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointStandaloneMmReadyToLockSecureStandaloneMmCommunicationBuffer (
  VOID
  )
{
  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToLockSecureStandaloneMmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //
  // Previous memory collection is allowed in StandaloneMm but leaving this function for possible future collection

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToLockSecureStandaloneMmCommunicationBuffer - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the Standalone MM page table at Standalone MM Ready To Boot.

  Test subject: Standalone MM page table.
  Test overview: Verify the Standalone MM page table matches the Standalone MM memory attribute table.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Reports an error message upon checking.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointStandaloneMmReadyToBootStandaloneMmPageProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtection - Enter\n"));

  Result = TRUE;

  Status = TestPointCheckStandaloneMmPaging ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      6,
      TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION
      );
  }

  if (mUefiMemoryMap != NULL) {
    Result = TRUE;

    Status = TestPointCheckStandaloneMmCommunicationBuffer (mUefiMemoryMap, mUefiMemoryMapSize, mUefiDescriptorSize, mUefiMemoryAttributesTable);
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    }
    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        6,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    }
  }
  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtection - Exit\n"));
  return EFI_SUCCESS;
}

/**
  Dispatch function for a Software SMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-Standalone MM environment into an Standalone MM environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler (
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO      *CommData;
  UINTN                                               TempCommBufferSize;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler - Enter\n"));

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize < sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: SMM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  if (!MmCommBufferValid((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: SMM communication buffer in SMRAM or overflow!\n"));
    return EFI_SUCCESS;
  }
  DEBUG ((DEBUG_INFO, "TempCommBufferSize - 0x%x\n", TempCommBufferSize));
  CommData = AllocateCopyPool (TempCommBufferSize, CommBuffer);
  if (CommData == NULL) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: SMM communication buffer size too big!\n"));
    return EFI_SUCCESS;
  }
  if (CommData->UefiMemoryMapOffset != sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryMapSize >= TempCommBufferSize - CommData->UefiMemoryMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->GcdMemoryMapOffset != CommData->UefiMemoryMapOffset + CommData->UefiMemoryMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdMemoryMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->GcdMemoryMapSize >= TempCommBufferSize - CommData->GcdMemoryMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdMemoryMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->GcdIoMapOffset != CommData->GcdMemoryMapOffset + CommData->GcdMemoryMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdIoMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->GcdIoMapSize >= TempCommBufferSize - CommData->GcdIoMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdIoMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryAttributeTableOffset != CommData->GcdIoMapOffset + CommData->GcdIoMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryAttributeTableOffset invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryAttributeTableSize != TempCommBufferSize - CommData->UefiMemoryAttributeTableOffset) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryAttributeTableSize invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryMapSize != 0) {
    //
    // The SpeculationBarrier() call here is to ensure the previous range/content
    // checks for the CommBuffer (copied in to CommData) have been completed before
    // calling into TestPointCheckStandaloneMmCommunicationBuffer().
    //
    SpeculationBarrier ();
    Result = TRUE;

    Status = TestPointCheckStandaloneMmCommunicationBuffer (
               (EFI_MEMORY_DESCRIPTOR *)(UINTN)((UINTN)CommData + CommData->UefiMemoryMapOffset),
               (UINTN)CommData->UefiMemoryMapSize,
               mUefiDescriptorSize,
               (CommData->UefiMemoryAttributeTableSize != 0) ? (EFI_MEMORY_ATTRIBUTES_TABLE *)(UINTN)((UINTN)CommData + CommData->UefiMemoryAttributeTableOffset) : NULL
               );
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    }
    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        6,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    } else {
      TestPointLibClearFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        6,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    }
  }
Done:
  FreePool (CommData);

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler - Exit\n"));
  return EFI_SUCCESS;
}

/**
  Dispatch function for a Software SMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param Context         Points to an optional handler context which was specified when the
                         handler was registered.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-Standalone MM environment into an Standalone MM environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
EFIAPI
TestPointStandaloneMmHandler (
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
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmHandler: SMM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }
  CopyMem (&CommData, CommBuffer, sizeof(CommData));
  if (CommData.Version != TEST_POINT_SMM_COMMUNICATION_VERSION) {
    DEBUG((DEBUG_ERROR, "TestPointStandaloneMmHandler: SMM communication Version invalid!\n"));
    return EFI_SUCCESS;
  }
  switch (CommData.FuncId) {
  case TEST_POINT_SMM_COMMUNICATION_FUNC_ID_UEFI_GCD_MAP_INFO:
    return TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler (CommBuffer, CommBufferSize);
  }
  return EFI_SUCCESS;
}

/**
  This service verifies the system state within SMM after Exit Boot Services is invoked.

  @retval EFI_SUCCESS         The test point check was performed successfully.
**/
EFI_STATUS
EFIAPI
TestPointStandaloneMmExitBootServices (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmExitBootServices - Enter\n"));

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmExitBootServices - Exit\n"));
  return EFI_SUCCESS;
}

/**
  Register StandaloneMM Test Point handler.
**/
VOID
RegisterStandaloneMmTestPointHandler (
  VOID
  )
{
  EFI_STATUS    Status;
  EFI_HANDLE    DispatchHandle;

  Status = gMmst->MmiHandlerRegister (
                    TestPointStandaloneMmHandler,
                    &mTestPointSmmCommunciationGuid,
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
  The library constructuor.

  The function does the necessary initialization work for this library
  instance.

  @param[in]  ImageHandle       The firmware allocated handle for the UEFI image.
  @param[in]  SystemTable       A pointer to the EFI system table.

  @retval     EFI_SUCCESS       The function always return EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
StandaloneMmTestPointCheckLibConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_MM_SYSTEM_TABLE *SystemTable
  )
{
  InitData (PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV);

  RegisterStandaloneMmTestPointHandler ();

  return EFI_SUCCESS;
}
