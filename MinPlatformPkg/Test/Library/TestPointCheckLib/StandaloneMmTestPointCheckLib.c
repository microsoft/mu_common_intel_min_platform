/** @file
This file contains Standalone MM specific implementations that
are an abstraction used by the generic MM testpoint file to perform
required tests.

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
#include <Library/StandaloneMmMemLib.h>
#include <Library/MmServicesTableLib.h>
#include <Guid/MemoryAttributesTable.h>

#include "TestPointInternal.h"
#include "TestPointMm.h"

GLOBAL_REMOVE_IF_UNREFERENCED EFI_MEMORY_DESCRIPTOR  *mUefiMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                  mUefiMemoryMapSize;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                  mUefiDescriptorSize;

EFI_MEMORY_ATTRIBUTES_TABLE  *mUefiMemoryAttributesTable;

VOID
TestPointDumpMmLoadedImage (
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
  This service verifies the security of Standalone MM communication buffers at Standalone MM Ready To Lock.
  Test subject: Standalone MM communication buffer.
  Test overview: Verify only CommBuffer and MMIO are mapped in the page table.
  Reporting mechanism: Dumps the memory map and GCD map at StandaloneMmReadyToLock and checks at StandaloneMmReadyToBoot.
  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToLockSecureMmCommunicationBuffer (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

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
TestPointReadyToBootMmPageProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtection - Enter\n"));

  Result = TRUE;

  Status = TestPointCheckMmPaging ();
  if (EFI_ERROR (Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
      TEST_POINT_INDEX_BYTE6_SMM,
      TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION
      );
  }

  if (mUefiMemoryMap != NULL) {
    Result = TRUE;

    Status = TestPointCheckMmCommunicationBuffer (mUefiMemoryMap, mUefiMemoryMapSize, mUefiDescriptorSize, mUefiMemoryAttributesTable);
    if (EFI_ERROR (Status)) {
      Result = FALSE;
    }

    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
        TEST_POINT_INDEX_BYTE6_SMM,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    }
  }

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtection - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the Standalone MM memory attribute table at Standalone MM Ready To Lock.
  Test subject: Standalone MM memory attribute table.
  Test overview: Verify the Standalone MM memory attribute table is reported.
                 Verify image code/data is consistent with the Standalone MM memory attribute table.
                 Verify the GDT/IDT/PageTable is RO, data is NX, and code is RO.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the Standalone MM memory attribute table and Standalone MM image information.
  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToLockMmMemoryAttributeTableFunctional (
  VOID
  )
{
  return EFI_UNSUPPORTED;
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
TestPointReadyToBootMmPageProtectionHandler (
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS                                      Status;
  BOOLEAN                                         Result;
  TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO  *CommData;
  UINTN                                           TempCommBufferSize;

  DEBUG ((DEBUG_INFO, "======== TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler - Enter\n"));

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize < sizeof (TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: MM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  if (!MmCommBufferValid ((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: MM communication buffer in SMRAM or overflow!\n"));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "TempCommBufferSize - 0x%x\n", TempCommBufferSize));
  CommData = AllocateCopyPool (TempCommBufferSize, CommBuffer);
  if (CommData == NULL) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: MM communication buffer size too big!\n"));
    return EFI_SUCCESS;
  }

  if (CommData->UefiMemoryMapOffset != sizeof (TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryMapOffset invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryMapSize >= TempCommBufferSize - CommData->UefiMemoryMapOffset) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryMapSize invalid!\n"));
    goto Done;
  }

  if (CommData->GcdMemoryMapOffset != CommData->UefiMemoryMapOffset + CommData->UefiMemoryMapSize) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdMemoryMapOffset invalid!\n"));
    goto Done;
  }

  if (CommData->GcdMemoryMapSize >= TempCommBufferSize - CommData->GcdMemoryMapOffset) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdMemoryMapSize invalid!\n"));
    goto Done;
  }

  if (CommData->GcdIoMapOffset != CommData->GcdMemoryMapOffset + CommData->GcdMemoryMapSize) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdIoMapOffset invalid!\n"));
    goto Done;
  }

  if (CommData->GcdIoMapSize >= TempCommBufferSize - CommData->GcdIoMapOffset) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: GcdIoMapSize invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryAttributeTableOffset != CommData->GcdIoMapOffset + CommData->GcdIoMapSize) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryAttributeTableOffset invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryAttributeTableSize != TempCommBufferSize - CommData->UefiMemoryAttributeTableOffset) {
    DEBUG ((DEBUG_ERROR, "TestPointStandaloneMmReadyToBootStandaloneMmPageProtectionHandler: UefiMemoryAttributeTableSize invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryMapSize != 0) {
    //
    // The SpeculationBarrier() call here is to ensure the previous range/content
    // checks for the CommBuffer (copied in to CommData) have been completed before
    // calling into TestPointCheckMmCommunicationBuffer().
    //
    SpeculationBarrier ();
    Result = TRUE;

    Status = TestPointCheckMmCommunicationBuffer (
               (EFI_MEMORY_DESCRIPTOR *)(UINTN)((UINTN)CommData + CommData->UefiMemoryMapOffset),
               (UINTN)CommData->UefiMemoryMapSize,
               mUefiDescriptorSize,
               (CommData->UefiMemoryAttributeTableSize != 0) ? (EFI_MEMORY_ATTRIBUTES_TABLE *)(UINTN)((UINTN)CommData + CommData->UefiMemoryAttributeTableOffset) : NULL
               );
    if (EFI_ERROR (Status)) {
      Result = FALSE;
    }

    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
        TEST_POINT_INDEX_BYTE6_SMM,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    } else {
      TestPointLibClearFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM,
        TEST_POINT_INDEX_BYTE6_SMM,
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
  The library constructor.

  The function does the necessary initialization work for this library
  instance.

  @retval     EFI_SUCCESS       The function always return EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
StandaloneMmTestPointCheckLibConstructor (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  return MmTestPointCheckLibConstructor ();
}
