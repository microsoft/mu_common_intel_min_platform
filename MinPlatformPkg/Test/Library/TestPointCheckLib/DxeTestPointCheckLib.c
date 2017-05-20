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
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>

EFI_STATUS
TestPointDumpGcd (
  VOID
  );

EFI_STATUS
TestPointDumpMemMap (
  VOID
  );

EFI_STATUS
TestPointDumpMemAttribute (
  VOID
  );

EFI_STATUS
TestPointDumpPci (
  VOID
  );

EFI_STATUS
TestPointDumpConsoleVariable (
  VOID
  );

EFI_STATUS
TestPointDumpBootVariable (
  VOID
  );

EFI_STATUS
TestPointDumpDevicePath (
  VOID
  );

EFI_STATUS
TestPointDumpMemoryTypeInformation (
  VOID
  );

EFI_STATUS
TestPointDumpAcpi (
  VOID
  );

EFI_STATUS
TestPointDumpHsti (
  VOID
  );

EFI_STATUS
TestPointDumpVariable (
  VOID
  );

EFI_STATUS
TestPointDumpEsrt (
  VOID
  );

EFI_STATUS
TestPointDumpSmmInfo (
  VOID
  );

EFI_STATUS
TestPointDumpLoadedImage (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointPciEnumerationDone (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDone - Enter\n"));

  Result = TRUE;
  Status = TestPointDumpPci ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_PCI_ENUMERATION_DONE
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDone - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxe (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxe - Enter\n"));
  
  Result = TRUE;
  Status = TestPointDumpLoadedImage ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpMemMap ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpGcd ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpConsoleVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpBootVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_END_OF_DXE
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxe - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLock (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLock - Enter\n"));
  
  Result = TRUE;
  Status = TestPointDumpSmmInfo ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLock - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBoot (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBoot - Enter\n"));
  
  Result = TRUE;
  Status = TestPointDumpLoadedImage ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpMemMap ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpGcd ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpDevicePath ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpConsoleVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpBootVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpMemoryTypeInformation ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  Status = TestPointDumpMemAttribute ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpAcpi ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpEsrt ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  Status = TestPointDumpHsti ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_READY_TO_BOOT
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBoot - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointExitBootServices (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointExitBootServices - Enter\n"));

  DEBUG ((DEBUG_INFO, "======== TestPointExitBootServices - Exit\n"));

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
DxeTestPointCheckLibConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  InitData (PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV);

  return EFI_SUCCESS;
}
