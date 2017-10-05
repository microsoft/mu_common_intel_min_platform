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
  VOID
  );

VOID
TestPointDumpGcd (
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR **GcdMemoryMap,  OPTIONAL
  OUT UINTN                           *GcdMemoryMapNumberOfDescriptors,  OPTIONAL
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR     **GcdIoMap,  OPTIONAL
  OUT UINTN                           *GcdIoMapNumberOfDescriptors  OPTIONAL
  );

VOID
TestPointDumpUefiMemoryMap (
  OUT EFI_MEMORY_DESCRIPTOR **UefiMemoryMap, OPTIONAL
  OUT UINTN                 *UefiMemoryMapSize, OPTIONAL
  OUT UINTN                 *UefiDescriptorSize OPTIONAL
  );

GLOBAL_REMOVE_IF_UNREFERENCED EFI_MEMORY_DESCRIPTOR *mUefiMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiMemoryMapSize;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                 mUefiDescriptorSize;

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_MEMORY_SPACE_DESCRIPTOR *mGcdMemoryMap;
GLOBAL_REMOVE_IF_UNREFERENCED EFI_GCD_IO_SPACE_DESCRIPTOR     *mGcdIoMap;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdMemoryMapNumberOfDescriptors;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN                           mGcdIoMapNumberOfDescriptors;

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
  
  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_SMM_END_OF_DXE_SMRR_FUNCTIONAL) == 0) {
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
      TEST_POINT_BYTE5_SMM_END_OF_DXE_SMRR_FUNCTIONAL
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
  
  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
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
      5,
      TEST_POINT_BYTE5_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL
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
  
  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLockSecureSmmCommunicationBuffer - Enter\n"));

  //
  // Collect information here, because it is last chance to access outside SMRAM.
  //
  TestPointDumpUefiMemoryMap (&mUefiMemoryMap, &mUefiMemoryMapSize, &mUefiDescriptorSize);
  TestPointDumpGcd (&mGcdMemoryMap, &mGcdMemoryMapNumberOfDescriptors, &mGcdIoMap, &mGcdIoMapNumberOfDescriptors);
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
  
  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
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
      5,
      TEST_POINT_BYTE5_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION
      );
  }
  
  if (mUefiMemoryMap != NULL) {
    Result = TRUE;
  
    Status = TestPointCheckSmmCommunicationBuffer ();
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    }
    if (Result) {
      TestPointLibSetFeaturesVerified (
        PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
        NULL,
        5,
        TEST_POINT_BYTE5_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER
        );
    }
  }
  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBootSmmPageProtection - Exit\n"));
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

  return EFI_SUCCESS;
}
