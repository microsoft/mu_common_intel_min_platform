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
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/DmaRemappingReportingTable.h>
#include <IndustryStandard/WindowsSmmSecurityMitigationTable.h>

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

EFI_STATUS
TestPointCheckUefiMemoryMap (
  VOID
  );

EFI_STATUS
TestPointCheckUefiMemAttribute (
  VOID
  );

EFI_STATUS
TestPointCheckPciResource (
  VOID
  );

EFI_STATUS
TestPointCheckConsoleVariable (
  VOID
  );

EFI_STATUS
TestPointCheckBootVariable (
  VOID
  );

VOID
TestPointDumpDevicePath (
  VOID
  );

EFI_STATUS
TestPointCheckMemoryTypeInformation (
  VOID
  );

EFI_STATUS
TestPointCheckAcpi (
  IN UINT32  *Signature OPTIONAL
  );

EFI_STATUS
TestPointCheckHsti (
  VOID
  );

VOID
TestPointDumpVariable (
  VOID
  );

EFI_STATUS
TestPointCheckEsrt (
  VOID
  );

EFI_STATUS
TestPointCheckSmmInfo (
  VOID
  );

EFI_STATUS
TestPointCheckPciBusMaster (
  VOID
  );

EFI_STATUS
TestPointCheckLoadedImage (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointCheckSmiHandlerInstrument (
  VOID
  );

EFI_STATUS
TestPointCheckUefiSecureBoot (
  VOID
  );

EFI_STATUS
TestPointCheckPiSignedFvBoot (
  VOID
  );

EFI_STATUS
TestPointCheckTcgTrustedBoot (
  VOID
  );

EFI_STATUS
TestPointCheckTcgMor (
  VOID
  );

GLOBAL_REMOVE_IF_UNREFERENCED ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT  mTestPointStruct = {
  PLATFORM_TEST_POINT_VERSION,
  PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
  {TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE},
  TEST_POINT_FEATURE_SIZE,
  {0}, // FeaturesImplemented
  {0}, // FeaturesVerified
  0,
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mFeatureImplemented[TEST_POINT_FEATURE_SIZE];

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciBusMasterDisabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_PCI_BUS_MASTER_DISABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciBusMasterDisabled - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckPciBusMaster ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_PCI_BUS_MASTER_DISABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciBusMasterDisabled - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciResourceAllocated (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciResourceAllocated - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckPciResource ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciResourceAllocated - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxeDmarTableFuntional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT32      Signature;
  
  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_END_OF_DXE_DMAT_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmarTableFuntional - Enter\n"));
  
  Signature = EFI_ACPI_4_0_DMA_REMAPPING_TABLE_SIGNATURE;
  Result = TRUE;
  Status = TestPointCheckAcpi (&Signature);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_END_OF_DXE_DMAT_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmarTableFuntional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxeNoThirdPartyPciOptionRom (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeNoThirdPartyPciOptionRom - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckLoadedImage ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeNoThirdPartyPciOptionRom - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockSmramAligned (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockSmramAligned - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckSmmInfo ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockSmramAligned - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockWsmtTableFuntional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  UINT32      Signature;
  
  if ((mFeatureImplemented[2] & TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockWsmtTableFuntional - Enter\n"));
  
  Result = TRUE;
  Signature = EFI_ACPI_WINDOWS_SMM_SECURITY_MITIGATION_TABLE_SIGNATURE;
  Status = TestPointCheckAcpi (&Signature);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      2,
      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockWsmtTableFuntional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootSmiHandlerInstrument (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootSmiHandlerInstrument - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckSmiHandlerInstrument ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootSmiHandlerInstrument - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootAcpiTableFuntional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootAcpiTableFuntional - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckAcpi (NULL);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootAcpiTableFuntional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootMemoryTypeInformationFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootMemoryTypeInformationFunctional - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckMemoryTypeInformation ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  TestPointDumpUefiMemoryMap (NULL, NULL, NULL);
  Status = TestPointCheckUefiMemoryMap ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootMemoryTypeInformationFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiMemoryAttributeTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiMemoryAttributeTableFunctional - Enter\n"));
  
  Result = TRUE;
  TestPointDumpUefiMemoryMap (NULL, NULL, NULL);
  TestPointDumpGcd (NULL, NULL, NULL, NULL);
  Status = TestPointCheckUefiMemAttribute ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiMemoryAttributeTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiBootVariableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiBootVariableFunctional - Enter\n"));
  
  Result = TRUE;
  TestPointDumpDevicePath ();
  TestPointDumpVariable ();
  Status = TestPointCheckBootVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiBootVariableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiConsoleVariableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiConsoleVariableFunctional - Enter\n"));
  
  Result = TRUE;
  TestPointDumpDevicePath ();
  TestPointDumpVariable ();
  Status = TestPointCheckConsoleVariable ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiConsoleVariableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootHstiTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootHstiTableFunctional - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckHsti ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootHstiTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootEsrtTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootEsrtTableFunctional - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckEsrt ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootEsrtTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiSecureBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiSecureBootEnabled - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckUefiSecureBoot ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiSecureBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootPiSignedFvBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootPiSignedFvBootEnabled - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckPiSignedFvBoot ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootPiSignedFvBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgTrustedBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgTrustedBootEnabled - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckTcgTrustedBoot ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgTrustedBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgMorEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;
  
  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_TCG_MOR_ENABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgMorEnabled - Enter\n"));
  
  Result = TRUE;
  Status = TestPointCheckTcgMor ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  
  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_TCG_MOR_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgMorEnabled - Exit\n"));
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
