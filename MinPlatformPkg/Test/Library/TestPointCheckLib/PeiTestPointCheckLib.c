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
TestPointCheckMtrr (
  IN BOOLEAN   IsForDxe
  );

EFI_STATUS
TestPointDumpHob (
  IN BOOLEAN  PhitHobOnly
  );

EFI_STATUS
TestPointCheckFvInfo (
  VOID
  );

EFI_STATUS
TestPointCheckMemoryResource (
  VOID
  );

EFI_STATUS
TestPointCheckSmramHob (
  VOID
  );

EFI_STATUS
TestPointCheckSmmInfoPei (
  VOID
  );

EFI_STATUS
TestPointCheckPciBusMaster (
  VOID
  );

GLOBAL_REMOVE_IF_UNREFERENCED ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  mTestPointStruct = {
  PLATFORM_TEST_POINT_VERSION,
  PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
  {TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI},
  TEST_POINT_FEATURE_SIZE,
  {0}, // FeaturesImplemented
  {0}, // FeaturesVerified
  0,
};

UINT8 *
GetFeatureImplemented (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *TestPoint;
  UINTN       TestPointSize;

  Status = TestPointLibGetTable (
             PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
             TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI,
             &TestPoint,
             &TestPointSize
             );
  ASSERT_EFI_ERROR(Status);

  return (UINT8 *)TestPoint + sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT);
}

EFI_STATUS
EFIAPI
TestPointDebugInitDone (
  VOID
  )
{
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();

  //
  // If code can run here, always set TEMP INIT DONE here.
  //
  TestPointLibSetFeaturesVerified (
    PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
    NULL,
    0,
    TEST_POINT_BYTE0_TEMP_INIT_DONE
    );

  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_DEBUG_INIT_DONE) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDebugInitDone - Enter\n"));
  DEBUG ((DEBUG_INFO, "!!! DebugInitialized !!!\n"));

  TestPointLibSetFeaturesVerified (
    PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
    NULL,
    1,
    TEST_POINT_BYTE1_DEBUG_INIT_DONE
    );
  DEBUG ((DEBUG_INFO, "======== TestPointDebugInitDone - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMtrrFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredMtrrFunctional - Enter\n"));

  TestPointDumpHob (FALSE);

  Result = TRUE;
  Status = TestPointCheckMtrr (FALSE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredMtrrFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMemoryResourceFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_MEMORY_DISCOVERED_MEMORY_RESOURCE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredMemoryResourceFunctional - Enter\n"));
  Result = TRUE;

  Status = TestPointCheckMemoryResource ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_MEMORY_DISCOVERED_MEMORY_RESOURCE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredMemoryResourceFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredFvInfoFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_MEMORY_DISCOVERED_FV_INFO_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredFvInfoFunctional - Enter\n"));
  Result = TRUE;
  Status = TestPointCheckFvInfo ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_MEMORY_DISCOVERED_FV_INFO_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointMemoryDiscoveredFvInfoFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiSystemResourceFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_END_OF_PEI_SYSTEM_RESOURCE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiSystemResourceFunctional - Enter\n"));

  TestPointDumpHob (FALSE);

  Result = TRUE;
  Status = TestPointCheckSmmInfoPei ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_END_OF_PEI_SYSTEM_RESOURCE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiSystemResourceFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiMtrrFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_END_OF_PEI_MTRR_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiMtrrFunctional - Enter\n"));
  Result = TRUE;
  Status = TestPointCheckMtrr (TRUE);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_END_OF_PEI_MTRR_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiMtrrFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiPciBusMasterDisabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT8       *FeatureImplemented;

  FeatureImplemented = GetFeatureImplemented ();
  
  if ((FeatureImplemented[1] & TEST_POINT_BYTE1_END_OF_PEI_PCI_BUS_MASTER_DISABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiPciBusMasterDisabled - Enter\n"));
  Result = TRUE;
  Status = TestPointCheckPciBusMaster ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      1,
      TEST_POINT_BYTE1_END_OF_PEI_PCI_BUS_MASTER_DISABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfPeiPciBusMasterDisabled - Exit\n"));
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
