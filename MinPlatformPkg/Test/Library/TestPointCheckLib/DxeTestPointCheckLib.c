/** @file

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SafeIntLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DeviceSpecificBusInfoLib.h>
#include <Library/SecuredCoreProductDataAccessLib.h>      // GetNextProductDataItem
#include <Library/MemoryAllocationLib.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/DmaRemappingReportingTable.h>
#include <IndustryStandard/WindowsSmmSecurityMitigationTable.h>
#include <IndustryStandard/PciExpress21.h>
#include <Protocol/SmmCommunication.h>
#include <Protocol/PciIo.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

#include "TestPointInternal.h"
// MU_CHANGE [BEGIN] - Support platform level configuration testing
#include <Library/PlatformConfigCheckLib.h>
// MU_CHANGE [END]

GLOBAL_REMOVE_IF_UNREFERENCED EFI_GUID mTestPointSmmCommunciationGuid = TEST_POINT_SMM_COMMUNICATION_GUID;

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
  VOID
  );

EFI_STATUS
TestPointCheckAcpiGcdResource (
  VOID
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

EFI_STATUS
TestPointVtdEngine (
  VOID
  );

VOID *
TestPointGetAcpi (
  IN UINT32  Signature
  );

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePcieGenSpeed (
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

/**
  This service verifies bus master enable (BME) is disabled after PCI enumeration.

  Test subject: PCI device BME.
  Test overview: Verify BME is cleared.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps results to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciBusMasterDisabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED) == 0) {
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
      3,
      TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciBusMasterDisabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies PCI device resource assignment after PCI enumeration.

  Test subject: PCI device resources.
  Test overview: Verify all PCI devices have been assigned proper resources.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps PCI resource assignments to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciResourceAllocated (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED) == 0) {
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
      3,
      TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePciResourceAllocated - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the DMA ACPI table is reported at the end of DXE.

  Test subject: DMA protection.
  Test overview: DMA ACPI table is reported.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the DMA ACPI table to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointEndOfDxeDmaAcpiTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *Acpi;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmaAcpiTableFunctional - Enter\n"));

  Acpi = TestPointGetAcpi (EFI_ACPI_4_0_DMA_REMAPPING_TABLE_SIGNATURE);
  if (Acpi == NULL) {
    DEBUG ((DEBUG_ERROR, "No DMAR table\n"));
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL_ERROR_CODE \
        TEST_POINT_END_OF_DXE \
        TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL_ERROR_STRING
      );
    Status = EFI_INVALID_PARAMETER;
  } else {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL
      );
    Status = EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmaAcpiTableFunctional - Exit\n"));
  return Status;
}

/**
  This service verifies DMA protection configuration at the end of DXE.

  Test subject: DMA protection.
  Test overview: DMA protection in DXE.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the DMA ACPI table to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointEndOfDxeDmaProtectionEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_END_OF_DXE_DMA_PROTECTION_ENABLED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmaProtectionEnabled - Enter\n"));

  Result = TRUE;
  Status = TestPointVtdEngine ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      3,
      TEST_POINT_BYTE3_END_OF_DXE_DMA_PROTECTION_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeDmaProtectionEnabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies no 3rd party PCI option ROMs (OPROMs) were dispatched prior to the end of DXE.

  Test subject: 3rd party OPROMs.
  Test overview: Verify no 3rd party PCI OPROMs were .
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps PCI resource assignments to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointEndOfDxeNoThirdPartyPciOptionRom (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM) == 0) {
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
      3,
      TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointEndOfDxeNoThirdPartyPciOptionRom - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of System Management RAM (SMRAM) alignment at SMM Ready To Lock.

  Test subject: SMRAM Information.
  Test overview: SMRAM is aligned.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the SMRAM region table to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockSmramAligned (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[7] & TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED) == 0) {
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
      7,
      TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockSmramAligned - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the Windows SMM Security Mitigation Table (WSMT) at SMM Ready To Lock.

  Test subject: Windows Security SMM Mitigation Table.
  Test overview: The table is reported in compliance with the Windows SMM Security Mitigations Table
                 ACPI table specification.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the WSMT to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockWsmtTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *Acpi;

  if ((mFeatureImplemented[7] & TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockWsmtTableFunctional - Enter\n"));

  Acpi = TestPointGetAcpi (EFI_ACPI_WINDOWS_SMM_SECURITY_MITIGATION_TABLE_SIGNATURE);
  if (Acpi == NULL) {
    DEBUG ((DEBUG_ERROR, "No WSMT table\n"));
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL_ERROR_CODE \
        TEST_POINT_DXE_SMM_READY_TO_LOCK \
        TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL_ERROR_STRING
      );
    Status = EFI_INVALID_PARAMETER;
  } else {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      7,
      TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL
      );
    Status = EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToLockWsmtTableFunctional - Exit\n"));
  return Status;
}

/**
  This service verifies the validity of the SMM page table at Ready To Boot.

  Test subject: SMM page table.
  Test overview: The SMM page table settings matches the SmmMemoryAttribute table.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Reports an error if verification fails.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToBootSmmPageProtection (
  VOID
  )
{
  EFI_MEMORY_DESCRIPTOR                               *UefiMemoryMap;
  UINTN                                               UefiMemoryMapSize;
  UINTN                                               UefiDescriptorSize;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR                     *GcdMemoryMap;
  EFI_GCD_IO_SPACE_DESCRIPTOR                         *GcdIoMap;
  UINTN                                               GcdMemoryMapNumberOfDescriptors;
  UINTN                                               GcdIoMapNumberOfDescriptors;
  EFI_MEMORY_ATTRIBUTES_TABLE                         *MemoryAttributesTable;
  UINTN                                               MemoryAttributesTableSize;
  EFI_STATUS                                          Status;
  UINTN                                               CommSize;
  UINT64                                              LongCommSize;
  UINT8                                               *CommBuffer;
  EFI_SMM_COMMUNICATE_HEADER                          *CommHeader;
  EFI_SMM_COMMUNICATION_PROTOCOL                      *SmmCommunication;
  UINTN                                               MinimalSizeNeeded;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE             *PiSmmCommunicationRegionTable;
  UINT32                                              Index;
  EFI_MEMORY_DESCRIPTOR                               *Entry;
  UINTN                                               Size;
  TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO      *CommData;

  if ((mFeatureImplemented[6] & TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToBootSmmPageProtection - Enter\n"));

  TestPointDumpUefiMemoryMap (&UefiMemoryMap, &UefiMemoryMapSize, &UefiDescriptorSize, FALSE);
  TestPointDumpGcd (&GcdMemoryMap, &GcdMemoryMapNumberOfDescriptors, &GcdIoMap, &GcdIoMapNumberOfDescriptors, FALSE);

  MemoryAttributesTable = NULL;
  MemoryAttributesTableSize = 0;
  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    MemoryAttributesTableSize = sizeof(EFI_MEMORY_ATTRIBUTES_TABLE) + MemoryAttributesTable->DescriptorSize * MemoryAttributesTable->NumberOfEntries;
  }

  Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (VOID **)&SmmCommunication);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "TestPointDxeSmmReadyToBootSmmPageProtection: Locate SmmCommunication protocol - %r\n", Status));
    return EFI_SUCCESS;
  }

  MinimalSizeNeeded = OFFSET_OF(EFI_SMM_COMMUNICATE_HEADER, Data) +
                      sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO) +
                      UefiMemoryMapSize +
                      GcdMemoryMapNumberOfDescriptors * sizeof(EFI_GCD_MEMORY_SPACE_DESCRIPTOR) +
                      GcdIoMapNumberOfDescriptors * sizeof(EFI_GCD_IO_SPACE_DESCRIPTOR) +
                      MemoryAttributesTableSize;

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "TestPointDxeSmmReadyToBootSmmPageProtection: Get PiSmmCommunicationRegionTable - %r\n", Status));
    return EFI_SUCCESS;
  }
  ASSERT(PiSmmCommunicationRegionTable != NULL);
  Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  Size = 0;
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE((UINTN)Entry->NumberOfPages);
      if (Size >= MinimalSizeNeeded) {
        break;
      }
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT(Index < PiSmmCommunicationRegionTable->NumberOfEntries);
  CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

  CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
  CopyMem(&CommHeader->HeaderGuid, &mTestPointSmmCommunciationGuid, sizeof(mTestPointSmmCommunciationGuid));
  CommHeader->MessageLength = MinimalSizeNeeded - OFFSET_OF(EFI_SMM_COMMUNICATE_HEADER, Data);

  CommData = (TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO *)&CommBuffer[OFFSET_OF(EFI_SMM_COMMUNICATE_HEADER, Data)];
  CommData->Header.Version      = TEST_POINT_SMM_COMMUNICATION_VERSION;
  CommData->Header.FuncId       = TEST_POINT_SMM_COMMUNICATION_FUNC_ID_UEFI_GCD_MAP_INFO;
  CommData->Header.Size         = CommHeader->MessageLength;
  CommData->UefiMemoryMapOffset = sizeof(TEST_POINT_SMM_COMMUNICATION_UEFI_GCD_MAP_INFO);
  CommData->UefiMemoryMapSize   = UefiMemoryMapSize;
  CommData->GcdMemoryMapOffset  = CommData->UefiMemoryMapOffset + CommData->UefiMemoryMapSize;
  CommData->GcdMemoryMapSize    = GcdMemoryMapNumberOfDescriptors * sizeof(EFI_GCD_MEMORY_SPACE_DESCRIPTOR);
  CommData->GcdIoMapOffset      = CommData->GcdMemoryMapOffset + CommData->GcdMemoryMapSize;
  CommData->GcdIoMapSize        = GcdIoMapNumberOfDescriptors * sizeof(EFI_GCD_IO_SPACE_DESCRIPTOR);
  CommData->UefiMemoryAttributeTableOffset = CommData->GcdIoMapOffset + CommData->GcdIoMapSize;
  CommData->UefiMemoryAttributeTableSize   = MemoryAttributesTableSize;

  CopyMem (
    (VOID *)(UINTN)((UINTN)CommData + CommData->UefiMemoryMapOffset),
    UefiMemoryMap,
    (UINTN)CommData->UefiMemoryMapSize
    );
  CopyMem (
    (VOID *)(UINTN)((UINTN)CommData + CommData->GcdMemoryMapOffset),
    GcdMemoryMap,
    (UINTN)CommData->GcdMemoryMapSize
    );
  CopyMem (
    (VOID *)(UINTN)((UINTN)CommData + CommData->GcdIoMapOffset),
    GcdIoMap,
    (UINTN)CommData->GcdIoMapSize
    );
  CopyMem (
    (VOID *)(UINTN)((UINTN)CommData + CommData->UefiMemoryAttributeTableOffset),
    MemoryAttributesTable,
    (UINTN)CommData->UefiMemoryAttributeTableSize
    );

  Status = SafeUint64Add (OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data), CommHeader->MessageLength, &LongCommSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "TestPointDxeSmmReadyToBootSmmPageProtection: LongCommSize calculation - %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = SafeUint64ToUintn (LongCommSize, &CommSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "TestPointDxeSmmReadyToBootSmmPageProtection: CommSize conversion - %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = SmmCommunication->Communicate(SmmCommunication, CommBuffer, &CommSize);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "TestPointDxeSmmReadyToBootSmmPageProtection: SmmCommunication - %r\n", Status));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToBootSmmPageProtection - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies SMI handler profiling.

  Test subject: SMI handler profiling.
  Test overview:
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the SMI handler profile.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToBootSmiHandlerInstrument (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[7] & TEST_POINT_BYTE7_DXE_SMM_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToBootSmiHandlerInstrument - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckSmiHandlerInstrument ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      7,
      TEST_POINT_BYTE7_DXE_SMM_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointDxeSmmReadyToBootSmiHandlerInstrument - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This services verifies the validity of installed ACPI tables at Ready To Boot.

  Test subject: ACPI tables.
  Test overview: The ACPI table settings are valid.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the installed ACPI tables.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootAcpiTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootAcpiTableFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckAcpi ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootAcpiTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This services verifies ACPI table resources are in the GCD.

  Test subject: ACPI memory resources.
  Test overview: Memory resources are in both ACPI and GCD.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the installed ACPI tables and GCD.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootGcdResourceFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_GCD_RESOURCE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootGcdResourceFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckAcpiGcdResource ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_GCD_RESOURCE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootGcdResourceFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the memory type information settings.

  Test subject: Memory type information.
  Test overview: Inspect an verify memory type information is correct.
                 Confirm no fragmentation exists in the ACPI/Reserved/Runtime regions.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the memory type information settings to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootMemoryTypeInformationFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootMemoryTypeInformationFunctional - Enter\n"));

  Result = TRUE;
  Status = TestPointCheckMemoryTypeInformation ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }
  TestPointDumpUefiMemoryMap (NULL, NULL, NULL, TRUE);
  Status = TestPointCheckUefiMemoryMap ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootMemoryTypeInformationFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the memory type information settings.

  Test subject: Memory type information.
  Test overview: Inspect an verify memory type information is correct.
                 Confirm no fragmentation exists in the ACPI/Reserved/Runtime regions.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the memory type information settings to the debug log.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootUefiMemoryAttributeTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiMemoryAttributeTableFunctional - Enter\n"));

  Result = TRUE;
  TestPointDumpUefiMemoryMap (NULL, NULL, NULL, TRUE);
  TestPointDumpGcd (NULL, NULL, NULL, NULL, TRUE);
  Status = TestPointCheckUefiMemAttribute ();
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (Result) {
    TestPointLibSetFeaturesVerified (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiMemoryAttributeTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the validity of the UEFI memory attribute table.

  Test subject: UEFI memory attribute table.
  Test overview: The UEFI memeory attribute table is reported. The image code/data is consistent with the table.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the UEFI image information and the UEFI memory attribute table.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootUefiBootVariableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL) == 0) {
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
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiBootVariableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the consle variable information.

  Test subject: Console.
  Test overview: Inspect and verify the console variable information is correct.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the console variable information.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootUefiConsoleVariableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[4] & TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL) == 0) {
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
      4,
      TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiConsoleVariableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the HSTI table.

  Test subject: HSTI table.
  Test overview: Verify the HSTI table is reported.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the HSTI table.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootHstiTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[8] & TEST_POINT_BYTE8_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL) == 0) {
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
      8,
      TEST_POINT_BYTE8_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootHstiTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the ESRT table.

  Test subject: ESRT table.
  Test overview: Verify the ESRT table is reported.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the ESRT table.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootEsrtTableFunctional (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[8] & TEST_POINT_BYTE8_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL) == 0) {
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
      8,
      TEST_POINT_BYTE8_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootEsrtTableFunctional - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies UEFI Secure Boot is enabled.

  Test subject: UEFI Secure Boot.
  Test overview: Verify the SecureBoot variable is set.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the SecureBoot variable.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootUefiSecureBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED) == 0) {
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
      5,
      TEST_POINT_BYTE5_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootUefiSecureBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies Platform Initialization (PI) Signed FV Boot is enabled.

  Test subject: PI Signed FV Boot.
  Test overview: Verify PI signed FV boot is enabled.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootPiSignedFvBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED) == 0) {
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
      5,
      TEST_POINT_BYTE5_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootPiSignedFvBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies TCG Trusted Boot is enabled.

  Test subject: TCG Trusted Boot.
  Test overview: Verify the TCG protocol is installed.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the TCG protocol capability.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootTcgTrustedBootEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED) == 0) {
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
      5,
      TEST_POINT_BYTE5_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgTrustedBootEnabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies TCG Memory Overwrite Request (MOR) is enabled.

  Test subject: TCG MOR.
  Test overview: Verify the MOR UEFI variable is set.
  Reporting mechanism: Set ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT.
                       Dumps the MOR UEFI variable.

  @retval EFI_SUCCESS         The test point check was performed successfully.
  @retval EFI_UNSUPPORTED     The test point check is not supported on this platform.
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootTcgMorEnabled (
  VOID
  )
{
  EFI_STATUS  Status;
  BOOLEAN     Result;

  if ((mFeatureImplemented[5] & TEST_POINT_BYTE5_READY_TO_BOOT_TCG_MOR_ENABLED) == 0) {
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
      5,
      TEST_POINT_BYTE5_READY_TO_BOOT_TCG_MOR_ENABLED
      );
  }

  DEBUG ((DEBUG_INFO, "======== TestPointReadyToBootTcgMorEnabled - Exit\n"));
  return EFI_SUCCESS;
}

/**
  This service verifies the system state after Exit Boot Services is invoked.

  @retval EFI_SUCCESS         The test point check was performed successfully.
**/
EFI_STATUS
EFIAPI
TestPointExitBootServices (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "======== TestPointExitBootServices - Enter\n"));
  // MU_CHANGE [BEGIN] - Support platform level configuration testing
  PlatformConfigDumpExitBootServices ();
  // MU_CHANGE [END]

  DEBUG ((DEBUG_INFO, "======== TestPointExitBootServices - Exit\n"));

  return EFI_SUCCESS;
}

/**
 Find a target capability block in PCI configuration space.

 @param[in]  PciIoDev           Pointer to EFI_PCI_IO_PROTOCOL
 @param[in]  DesiredPciCapId    Desired PCI capability ID
 @param[out] Offset             Pointer to Offset of Capability ID

 @retval EFI_SUCCESS            Capability was located and offset stored in *Offset
 @retval EFI_NOT_FOUND          Did not find the desired PCI capability
**/
EFI_STATUS
FindPciCapabilityPtr (
  EFI_PCI_IO_PROTOCOL *PciIoDev,
  UINT8 DesiredPciCapId,
  UINT32 *Offset
)
{
  UINT8 PciCapNext;
  UINT8 PciCapId;
  UINT16 PciCapHeader = 0;

  PciCapId = 0;
  PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint8, PCI_CAPBILITY_POINTER_OFFSET, 1, &PciCapNext);
  while ((PciCapId != DesiredPciCapId) && (PciCapNext != 0)) {
    PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint16, PciCapNext, 1, &PciCapHeader);
    PciCapId = PciCapHeader & 0xff;
    if (PciCapId == DesiredPciCapId) {
      break;
    }
    PciCapNext = PciCapHeader >> 8;
  }

  if (PciCapId == DesiredPciCapId) {
    *Offset = PciCapNext;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}
/**
 Test that required devices have trained to the required link speed.

 @retval EFI_SUCCESS            Test was performed and flagged as verified or error logged.
**/
EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePcieGenSpeed ()
{
  EFI_STATUS               Status;
  UINTN                    ProtocolCount;
  UINTN                    Seg;
  UINTN                    Bus;
  UINTN                    Dev;
  UINTN                    Fun;
  UINTN                    NumDevices;
  UINT32                   DevicesLength;
  UINTN                    OuterLoop;
  UINTN                    InnerLoop;
  EFI_PCI_IO_PROTOCOL      *PciIoDev;
  PCI_REG_PCIE_LINK_STATUS PcieLinkStatusReg;
  UINT32                   Offset;

  // To store protocols
  EFI_PCI_IO_PROTOCOL      **ProtocolList = NULL;

  // Array of pci info pointers. The ARRAY is freed, but the individual struct pointers pointed to
  // from within the array are not. This is to make the structs within the DeviceSpecificBusInfoLib
  // simpler by declaring them as globals
  DEVICE_PCI_INFO          *Devices = NULL;

  // Array parallel to Devices which we will use to check off which devices we've found
  BOOLEAN                  *DeviceFound = NULL;
  BOOLEAN                  AllDevicesFound = FALSE;

  if ((mFeatureImplemented[3] & TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePcieGenSpeed - Enter\n"));

  // Get the product data of devices to check
  Status = GetNextProductDataItem (ItemIdTestPointPciSpeed, &Devices, &DevicesLength);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[%a]: GetNextProductDataItem: %r\n", __FUNCTION__, Status));
    goto CLEANUP;
  }

  // TODO: complain if multiple productdatas, because we are only looking at the first?
  // Or handle multiple (probably not since having those in multiple locations sounds unnecessarily confusing for maintenance).

  // TODO?: validate data length?

  NumDevices = DevicesLength / sizeof(DEVICE_PCI_INFO);

  // Array to track which devices we've found
  DeviceFound = AllocateZeroPool (sizeof(BOOLEAN) * NumDevices);

  // Ensure that all necessary pointers have been populated, abort to cleanup if not
  if(Devices == NULL || DeviceFound == NULL || NumDevices == 0 ||
    EFI_ERROR (EfiLocateProtocolBuffer (&gEfiPciIoProtocolGuid, &ProtocolCount, (VOID*) &ProtocolList))) {
    goto CLEANUP;
  }

  // For each device protocol found...
  for(OuterLoop = 0; OuterLoop < ProtocolCount; OuterLoop++) {
    PciIoDev = ProtocolList[OuterLoop];

    // Get device location
    if(EFI_ERROR (PciIoDev->GetLocation (PciIoDev, &Seg, &Bus, &Dev, &Fun))) {
      continue;
    }

    // For each device supplied by DeviceSpecificBusInfoLib...
    for (InnerLoop = 0; InnerLoop < NumDevices; InnerLoop++) {
      // Check if that device matches the current protocol in OuterLoop
      if (Seg == Devices[InnerLoop].SegmentNumber && Bus == Devices[InnerLoop].BusNumber &&
          Dev == Devices[InnerLoop].DeviceNumber  && Fun == Devices[InnerLoop].FunctionNumber) {

        // Also check link speed.
        Status = FindPciCapabilityPtr (
                   PciIoDev,
                   EFI_PCI_CAPABILITY_ID_PCIEXP,
                   &Offset
                   );
        ASSERT_EFI_ERROR (Status);

        Offset += OFFSET_OF (PCI_CAPABILITY_PCIEXP, LinkStatus);
        PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint16, Offset, 1, &PcieLinkStatusReg.Uint16);
        DEBUG ((DEBUG_INFO, "[%a] LinkStatusReg = %04x\n", __FUNCTION__, PcieLinkStatusReg.Uint16));
        if (PcieLinkStatusReg.Bits.CurrentLinkSpeed >= Devices[InnerLoop].MinimumLinkSpeed) {
          // If it matches, check it off in the parallel array
          DeviceFound[InnerLoop] = TRUE;
        }
      }
    }
  }

  // For each device supplied by DeviceSpecificBusInfoLib...
  AllDevicesFound = TRUE;
  for(OuterLoop = 0; OuterLoop < NumDevices; OuterLoop++) {

    // Check if the previous loop found that device
    if(DeviceFound[OuterLoop] == FALSE) {
      AllDevicesFound = FALSE;

      DEBUG ((
        DEBUG_INFO,
        "%a - %a not found. Expected Segment: %d  Bus: %d  Device: %d  Function: %d, MinimumLinkSpeed: %d\n",
        __FUNCTION__,
        Devices[OuterLoop].DeviceName,
        Devices[OuterLoop].SegmentNumber,
        Devices[OuterLoop].BusNumber,
        Devices[OuterLoop].DeviceNumber,
        Devices[OuterLoop].FunctionNumber,
        Devices[OuterLoop].MinimumLinkSpeed
        ));

    }
  }

  if (AllDevicesFound == TRUE) {
    Status = TestPointLibSetFeaturesVerified (
               PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
               NULL,
               3,
               TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] TestPointLibSetFeaturesVerified() failed - %r\n", __FUNCTION__, Status));
      ASSERT_EFI_ERROR (Status);
    }
  } else {
    Status = TestPointLibAppendErrorString (
               PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
               TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
               TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED_ERROR_CODE \
               TEST_POINT_PCI_ENUMERATION_DONE \
               TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED_ERROR_STRING
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] TestPointLibAppendErrorString() failed - %r\n", __FUNCTION__, Status));
      ASSERT_EFI_ERROR (Status);
    }
  }

CLEANUP:
  // Make sure everything is freed
  if (DeviceFound != NULL) {
    FreePool (DeviceFound);
  }

  if (ProtocolList != NULL) {
    FreePool (ProtocolList);
  }

  DEBUG ((DEBUG_INFO, "======== TestPointPciEnumerationDonePcieGenSpeed - Exit\n"));
  return EFI_SUCCESS;
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
  The library constructor.

  @param  ImageHandle   The firmware allocated handle for the EFI image.
  @param  SystemTable   A pointer to the EFI System Table.

  @retval EFI_SUCCESS   The function always return EFI_SUCCESS.
**/
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
