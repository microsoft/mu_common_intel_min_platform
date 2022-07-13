/** @file

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/SmmMemLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Guid/MemoryAttributesTable.h>

#include "TestPointInternal.h"

VOID
TestPointDumpGcd (
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR **GcdMemoryMap,  OPTIONAL
  OUT UINTN                           *GcdMemoryMapNumberOfDescriptors,  OPTIONAL
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR     **GcdIoMap,  OPTIONAL
  OUT UINTN                           *GcdIoMapNumberOfDescriptors,  OPTIONAL
  IN  BOOLEAN                         DumpPrint
  );

VOID
TestPointDumpUefiMemoryMap (
  OUT EFI_MEMORY_DESCRIPTOR **UefiMemoryMap, OPTIONAL
  OUT UINTN                 *UefiMemoryMapSize, OPTIONAL
  OUT UINTN                 *UefiDescriptorSize, OPTIONAL
  IN  BOOLEAN               DumpPrint
  );

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_MEMORY_SPACE_DESCRIPTOR *mGcdMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_IO_SPACE_DESCRIPTOR     *mGcdIoMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdMemoryMapNumberOfDescriptors;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdIoMapNumberOfDescriptors;

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
TestPointSmmEndOfDxeSmrrFunctional (
  VOID
  )
{
  TestPointMmEndOfDxeSmrrFunctional ();
}

/**
  This service verifies the validity of the SMM memory atttribute table at SMM Ready To Lock.

  Test subject: SMM memory attribute table.
  Test overview: Verify the SMM memory attribute table is reported.
                 Verify image code/data is consistent with the SMM memory attribute table.
                 Verify the GDT/IDT/PageTable is RO, data is NX, and code is RO.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the SMM memory attribute table and SMM image information.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSmmMemoryAttributeTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] &
    TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLock - Enter\n"));

  Result = TRUE;
  TestPointDumpSmmLoadedImage ();
  Status = TestPointCheckSmmMemAttribute ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_INDEX_BYTE6_SMM,
      TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLock - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the security of SMM communication buffers at SMM Ready To Lock.

  Test subject: SMM communication buffer.
  Test overview: Verify only CommBuffer and MMIO are mapped in the page table.
  Reporting mechanism: Dumps the memory map and GCD map at SmmReadyToLock and checks at SmmReadyToBoot.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSecureSmmCommunicationBuffer (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable;
  UINTN                        MemoryAttributesTableSize;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] &
    TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLockSecureSmmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //
  TestPointDumpUefiMemoryMap (&mUefiMemoryMap, &mUefiMemoryMapSize, &mUefiDescriptorSize, TRUE);
  TestPointDumpGcd (&mGcdMemoryMap, &mGcdMemoryMapNumberOfDescriptors, &mGcdIoMap, &mGcdIoMapNumberOfDescriptors, TRUE);

  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    MemoryAttributesTableSize = sizeof(EFI_MEMORY_ATTRIBUTES_TABLE) + MemoryAttributesTable->DescriptorSize * MemoryAttributesTable->NumberOfEntries;
    mUefiMemoryAttributesTable = AllocateCopyPool (MemoryAttributesTableSize, MemoryAttributesTable);
    ASSERT (mUefiMemoryAttributesTable != NULL);
  }
  //
  // Defer the validation to TestPointSmmReadyToBootSecureSmmCommunicationBuffer, because page table setup later.
  //

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLockSecureSmmCommunicationBuffer - Exit\n"));
  return EFI_SUCCESS;
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
TestPointSmmReadyToBootSmmPageProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[TEST_POINT_INDEX_BYTE6_SMM] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToBootMmPageProtection - Enter\n"));

  Result = TRUE;

  Status = TestPointCheckMmPaging ();
  if (EFI_ERROR (Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_INDEX_BYTE6_SMM,
      TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION
      );
  }

  if (mUefiMemoryMap != NULL) {
    Result = TRUE;

    Status = TestPointCheckSmmCommunicationBuffer (mUefiMemoryMap, mUefiMemoryMapSize, mUefiDescriptorSize, mUefiMemoryAttributesTable);
    if (EFI_ERROR (Status)) {
      Result = FALSE;
    }

    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        TEST_POINT_INDEX_BYTE6_SMM,
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    }
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMmReadyToBootMmPageProtection - Exit\n"));
  return EFI_SUCCESS;
}

/**
  Dispatch function for a Software SMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-SMM environment into an SMM environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
TestPointSmmReadyToBootSmmPageProtectionHandler (
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  TestPointMmReadyToBootMmPageProtectionHandler (CommBuffer, CommBufferSize);
}

/**
  Dispatch function for a Software SMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param Context         Points to an optional handler context which was specified when the
                         handler was registered.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-SMM environment into an SMM environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
EFIAPI
TestPointSmmHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  TestPointMmHandler (DispatchHandle, Context, CommBuffer, CommBufferSize);
}

/**
  This service verifies the system state within SMM after Exit Boot Services is invoked.

  @retval EFI_SUCCESS         The test point check was performed successfully.
**/
EFI_STATUS
EFIAPI
TestPointSmmExitBootServices (
  VOID
  )
{
  TestPointMmExitBootServices ();
}

/**
  Register SMM Test Point handler.
**/
VOID
RegisterSmmTestPointHandler (
  VOID
  )
{
  RegisterMmTestPointHandler ();
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
SmmTestPointCheckLibConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  MmTestPointCheckLibConstructor ();
}
