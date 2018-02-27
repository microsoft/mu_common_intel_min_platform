/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiSmm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/SmmMemLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Guid/MemoryAttributesTable.h>

#include "TestPointInternal.h"

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GUID mTestPointSmmCommunciationGuid = TEST_POINT_SMM_COMMUNICATION_GUID;

EFI_STATUS
TestPointCheckSmrr (
  VOID
  );

EFI_STATUS
TestPointDumpSmmLoadedImage (
  VOID
  );

EFI_STATUS
TestPointCheckSmmMemAttribute (
  VOID
  );

EFI_STATUS
TestPointCheckSmmPaging (
  VOID
  );

EFI_STATUS
TestPointCheckSmmCommunicationBuffer (
  IN EFI_MEMORY_DESCRIPTOR        *UefiMemoryMap,
  IN UINTN                        UefiMemoryMapSize,
  IN UINTN                        UefiDescriptorSize,
  IN EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable
  );

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

GLOBAL_REMOVE_IF_UNREFERENCED EFI_MEMORY_DESCRIPTOR *mUefiMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiMemoryMapSize;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiDescriptorSize;

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_MEMORY_SPACE_DESCRIPTOR *mGcdMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_IO_SPACE_DESCRIPTOR     *mGcdIoMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdMemoryMapNumberOfDescriptors;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdIoMapNumberOfDescriptors;

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

EFI_STATUS
EFIAPI
TestPointSmmEndOfDxeSmrrFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[5] & TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmEndOfDxeSmrrFunctional - Enter\n"));

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

  DEBUG ((DEBUG_INFO, "======== TestPointSmmEndOfDxe - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSmmMemoryAttributeTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[6] & TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
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
      6,
      TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLock - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSecureSmmCommunicationBuffer (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable;
  UINTN                        MemoryAttributesTableSize;

  if ((mFeatureImplemented[6] & TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLockSecureSmmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //
  TestPointDumpUefiMemoryMap (&mUefiMemoryMap, &mUefiMemoryMapSize, &mUefiDescriptorSize, TRUE);
  TestPointDumpGcd (&mGcdMemoryMap, &mGcdMemoryMapNumberOfDescriptors, &mGcdIoMap, &mGcdIoMapNumberOfDescriptors, TRUE);

  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, &MemoryAttributesTable);
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

EFI_STATUS
EFIAPI
TestPointSmmReadyToBootSmmPageProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[6] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBootSmmPageProtection - Enter\n"));
  
  Result = TRUE;
  
  Status = TestPointCheckSmmPaging ();
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
  
    Status = TestPointCheckSmmCommunicationBuffer (mUefiMemoryMap, mUefiMemoryMapSize, mUefiDescriptorSize, mUefiMemoryAttributesTable);
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
  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBootSmmPageProtection - Exit\n"));
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
  EFI_STATUS  Status;
  BOOLEAN     Result;
  TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO      *CommData;
  UINTN                                               TempCommBufferSize;
  
  if ((mFeatureImplemented[6] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBootSmmPageProtectionHandler - Enter\n"));

  TempCommBufferSize = *CommBufferSize;
  
  if (TempCommBufferSize < sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: SMM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  if (!SmmIsBufferOutsideSmmValid((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: SMM communication buffer in SMRAM or overflow!\n"));
    return EFI_SUCCESS;
  }
  DEBUG ((DEBUG_INFO, "TempCommBufferSize - 0x%x\n", TempCommBufferSize));
  CommData = AllocateCopyPool (TempCommBufferSize, CommBuffer);
  if (CommData == NULL) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: SMM communication buffer size too big!\n"));
    return EFI_SUCCESS;
  }
  if (CommData->UefiMemoryMapOffset != sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO)) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: UefiMemoryMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryMapSize >= TempCommBufferSize - CommData->UefiMemoryMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: UefiMemoryMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->GcdMemoryMapOffset != CommData->UefiMemoryMapOffset + CommData->UefiMemoryMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: GcdMemoryMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->GcdMemoryMapSize >= TempCommBufferSize - CommData->GcdMemoryMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: GcdMemoryMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->GcdIoMapOffset != CommData->GcdMemoryMapOffset + CommData->GcdMemoryMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: GcdIoMapOffset invalid!\n"));
    goto Done;
  }
  if (CommData->GcdIoMapSize >= TempCommBufferSize - CommData->GcdIoMapOffset) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: GcdIoMapSize invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryAttributeTableOffset != CommData->GcdIoMapOffset + CommData->GcdIoMapSize) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: UefiMemoryAttributeTableOffset invalid!\n"));
    goto Done;
  }
  if (CommData->UefiMemoryAttributeTableSize != TempCommBufferSize - CommData->UefiMemoryAttributeTableOffset) {
    DEBUG((DEBUG_ERROR, "TestPointSmmReadyToBootSmmPageProtectionHandler: UefiMemoryAttributeTableSize invalid!\n"));
    goto Done;
  }

  if (CommData->UefiMemoryMapSize != 0) {
    Result = TRUE;
  
    Status = TestPointCheckSmmCommunicationBuffer (
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

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBootSmmPageProtectionHandler - Exit\n"));
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
    DEBUG((DEBUG_ERROR, "TestPointSmmHandler: SMM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }
  CopyMem (&CommData, CommBuffer, sizeof(CommData));
  if (CommData.Version != TEST_POINT_SMM_COMMUNICATION_VERSION) {
    DEBUG((DEBUG_ERROR, "TestPointSmmHandler: SMM communication Version invalid!\n"));
    return EFI_SUCCESS;
  }
  switch (CommData.FuncId) {
  case TEST_POINT_SMM_COMMUNICATION_FUNC_ID_UEFI_GCD_MAP_INFO:
    return TestPointSmmReadyToBootSmmPageProtectionHandler (CommBuffer, CommBufferSize);
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmExitBootServices (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointSmmExitBootServices - Enter\n"));

  DEBUG ((DEBUG_INFO, "======== TestPointSmmExitBootServices - Exit\n"));
  return EFI_SUCCESS;
}

/**
  Register SMM Test Point handler.
**/
VOID
RegisterSmmTestPointHandler (
  VOID
  )
{
  EFI_STATUS    Status;
  EFI_HANDLE    DispatchHandle;

  Status = gSmst->SmiHandlerRegister (
                    TestPointSmmHandler,
                    &mTestPointSmmCommunciationGuid,
                    &DispatchHandle
                    );
  ASSERT_EFI_ERROR (Status);
}

/**
  Initialize feature data
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

EFI_STATUS
EFIAPI
SmmTestPointCheckLibConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  InitData (PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV);

  RegisterSmmTestPointHandler ();

  return EFI_SUCCESS;
}
