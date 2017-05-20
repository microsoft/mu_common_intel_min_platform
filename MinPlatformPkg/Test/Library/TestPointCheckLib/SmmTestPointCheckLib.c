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
TestPointDumpSmrr (
  VOID
  );

EFI_STATUS
TestPointDumpSmmLoadedImage (
  VOID
  );

EFI_STATUS
TestPointDumpSmmMemAttribute (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmEndOfDxe (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointSmmEndOfDxe - Enter\n"));
  
  Result = TRUE;
  Status = TestPointDumpSmmLoadedImage ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_SMM_END_OF_DXE
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmEndOfDxe - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLock (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLock - Enter\n"));

  Result = TRUE;
  Status = TestPointDumpSmrr ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpSmmMemAttribute ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_SMM_READY_TO_LOCK
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToLock - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToBoot (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBoot - Enter\n"));

  DEBUG ((DEBUG_INFO, "======== TestPointSmmReadyToBoot - Exit\n"));
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

GLOBAL_REMOVE_IF_UNREFERENCED ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  mTestPointStruct = {
  PLATFORM_TEST_POINT_VERSION,
  PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
  {TEST_POINT_IMPLEMENTATION_ID_PLATFORM},
  TEST_POINT_FEATURE_SIZE,
  {0}, // FeaturesRequired
  {0}, // FeaturesImplemented
  {0}, // FeaturesVerified
  0,
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mFeatureImplemented[TEST_POINT_FEATURE_SIZE];

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
