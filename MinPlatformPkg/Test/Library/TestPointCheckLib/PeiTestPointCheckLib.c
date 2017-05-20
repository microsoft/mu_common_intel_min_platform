/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <PiPei.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

EFI_STATUS
TestPointDumpMtrr (
  IN BOOLEAN   IsForDxe
  );

EFI_STATUS
TestPointDumpHob (
  IN BOOLEAN  PhitHobOnly
  );

EFI_STATUS
TestPointDumpFvInfo (
  VOID
  );

EFI_STATUS
TestPointDumpSmramHob (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDebugInitDone (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointDebugInitDone - Enter\n"));
  DEBUG ((DEBUG_INFO, "!!! DebugInitialized !!!\n"));

  Result = TRUE;
  Status = TestPointDumpHob (TRUE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_DEBUG_INIT_DONE
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDebugInitDone - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscovered (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscovered - Enter\n"));
  Result = TRUE;
  Status = TestPointDumpMtrr (FALSE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpHob (FALSE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpFvInfo ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpSmramHob ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_MEMORY_DISCOVERED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscovered - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPei (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPei - Enter\n"));
  Result = TRUE;
  Status = TestPointDumpMtrr (TRUE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpHob (FALSE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpFvInfo ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpSmramHob ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_END_OF_PEI
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPei - Exit\n"));
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

/**
  Initialize feature data
**/
VOID
InitData (
  IN UINT32                   Role
  )
{
  EFI_STATUS                               Status;
  UINT8                                    FeatureImplemented[TEST_POINT_FEATURE_SIZE];
  ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  TestPointStruct;

  ASSERT (PcdGetSize(PcdTestPointIbvPlatformFeature) == sizeof(FeatureImplemented));
  CopyMem (FeatureImplemented, PcdGetPtr(PcdTestPointIbvPlatformFeature), sizeof(FeatureImplemented));

  CopyMem (&TestPointStruct, &mTestPointStruct, sizeof(TestPointStruct));
  TestPointStruct.Role = Role;
  CopyMem (TestPointStruct.FeaturesImplemented, FeatureImplemented, sizeof(FeatureImplemented));
  Status = TestPointLibSetTable (
             &TestPointStruct,
             sizeof(TestPointStruct)
             );
  if (EFI_ERROR (Status)) {
    if (Status != EFI_ALREADY_STARTED) {
      ASSERT_EFI_ERROR (Status);
    }
  }
}

EFI_STATUS
EFIAPI
PeiTestPointCheckLibConstructor (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  InitData (PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV);

  return EFI_SUCCESS;
}
