/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _TEST_POINT_CHECK_LIB_H_
#define _TEST_POINT_CHECK_LIB_H_

#include <PiPei.h>
#include <Uefi.h>

//
// Below is Test Point Hook Point.
//
// Naming: TestPoint<Phase/Event><Function>
//
// Phase/Event(PEI) = MemoryDiscovered|EndOfPei
// Phase/Event(DXE) = PciEnumerationDone|EndOfDxe|DxeSmmReadyToLock|ReadyToBoot
// Phase/Event(SMM) = SmmEndOfDxe|SmmReadyToLock|SmmReadyToBoot
//

EFI_STATUS
EFIAPI
TestPointTempMemoryFunction (
  IN VOID   *TempRamStart,
  IN VOID   *TempRamEnd
  );

EFI_STATUS
EFIAPI
TestPointDebugInitDone (
  VOID
  );


EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMtrrFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMemoryResourceFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredFvInfoFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfPeiSystemResourceFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfPeiMtrrFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfPeiPciBusMasterDisabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciBusMasterDisabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciResourceAllocated (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfDxeDmaAcpiTableFuntional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfDxeNoThirdPartyPciOptionRom (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockSmramAligned (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockWsmtTableFuntional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToBootSmmPageProtection (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootAcpiTableFuntional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootMemoryTypeInformationFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiMemoryAttributeTableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiBootVariableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiConsoleVariableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootHstiTableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootEsrtTableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiSecureBootEnabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootPiSignedFvBootEnabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgTrustedBootEnabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgMorEnabled (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToBootSmiHandlerInstrument (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointExitBootServices (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmEndOfDxeSmrrFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSmmMemoryAttributeTableFunctional (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSecureSmmCommunicationBuffer (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmReadyToBootSmmPageProtection (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmExitBootServices (
  VOID
  );

//
// Below is detail definition for MinPlatform implementation
//

#define TEST_POINT_IMPLEMENTATION_ID_PLATFORM         L"Intel MinPlatform TestPoint"
#define TEST_POINT_IMPLEMENTATION_ID_PLATFORM_PEI     TEST_POINT_IMPLEMENTATION_ID_PLATFORM L" (PEI)"
#define TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE     TEST_POINT_IMPLEMENTATION_ID_PLATFORM L" (DXE)"
#define TEST_POINT_IMPLEMENTATION_ID_PLATFORM_SMM     TEST_POINT_IMPLEMENTATION_ID_PLATFORM L" (SMM)"

#define TEST_POINT_FEATURE_SIZE        0x10

#define TEST_POINT_ERROR                                                                    L"Error "
#define TEST_POINT_PLATFORM_TEST_POINT                                                      L" Platform TestPoint"

// Byte 0 - SEC/PEI
#define TEST_POINT_TEMP_MEMORY_INIT_DONE                                                    L" - Temp Memory Init Done - "
#define TEST_POINT_DEBUG_INIT_DONE                                                          L" - Debug Init Done - "

#define TEST_POINT_BYTE0_TEMP_INIT_DONE                                                     BIT0
#define TEST_POINT_BYTE0_DEBUG_INIT_DONE                                                    BIT1

// Byte 1/2 - PEI
#define TEST_POINT_MEMORY_DISCOVERED                                                        L" - Memory Discovered - "
#define TEST_POINT_END_OF_PEI                                                               L" - End Of PEI - "

#define TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL                                  BIT0
#define TEST_POINT_BYTE1_MEMORY_DISCOVERED_MEMORY_RESOURCE_FUNCTIONAL                       BIT1
#define TEST_POINT_BYTE1_MEMORY_DISCOVERED_FV_INFO_FUNCTIONAL                               BIT2
#define TEST_POINT_BYTE1_MEMORY_DISCOVERED_DMA_PROTECTION_ENABLED                           BIT3
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL_ERROR_CODE                          L"0x01000000"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_MTRR_FUNCTIONAL_ERROR_STRING                        L"Invalid MTRR Setting\r\n"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_MEMORY_RESOURCE_FUNCTIONAL_ERROR_CODE               L"0x01010000"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_MEMORY_RESOURCE_FUNCTIONAL_ERROR_STRING             L"Invalid Memory Resource\r\n"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_FV_INFO_FUNCTIONAL_ERROR_CODE                       L"0x01020000"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_FV_INFO_FUNCTIONAL_ERROR_STRING                     L"Invalid FV Information\r\n"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_DMA_PROTECTION_ENABLED_ERROR_CODE                   L"0x01030000"
#define   TEST_POINT_BYTE1_MEMORY_DISCOVERED_DMA_PROTECTION_ENABLED_ERROR_STRING                 L"DMA protection disabled\r\n"

#define TEST_POINT_BYTE2_END_OF_PEI_SYSTEM_RESOURCE_FUNCTIONAL                              BIT0
#define TEST_POINT_BYTE2_END_OF_PEI_MTRR_FUNCTIONAL                                         BIT1
#define TEST_POINT_BYTE2_END_OF_PEI_PCI_BUS_MASTER_DISABLED                                 BIT2
#define   TEST_POINT_BYTE2_END_OF_PEI_SYSTEM_RESOURCE_FUNCTIONAL_ERROR_CODE                      L"0x02000000"
#define   TEST_POINT_BYTE2_END_OF_PEI_SYSTEM_RESOURCE_FUNCTIONAL_ERROR_STRING                    L"Invalid System Resource\r\n"
#define   TEST_POINT_BYTE2_END_OF_PEI_MTRR_FUNCTIONAL_ERROR_CODE                                 L"0x02010000"
#define   TEST_POINT_BYTE2_END_OF_PEI_MTRR_FUNCTIONAL_ERROR_STRING                               L"Invalid MTRR Setting\r\n"
#define   TEST_POINT_BYTE2_END_OF_PEI_PCI_BUS_MASTER_DISABLED_ERROR_CODE                         L"0x02020000"
#define   TEST_POINT_BYTE2_END_OF_PEI_PCI_BUS_MASTER_DISABLED_ERROR_STRING                       L"PCI Bus Master Enabled\r\n"

// Byte 3/4/5 - DXE
#define TEST_POINT_PCI_ENUMERATION_DONE                                                     L" - PCI Enumeration Done - "
#define TEST_POINT_END_OF_DXE                                                               L" - End Of DXE - "
#define TEST_POINT_DXE_SMM_READY_TO_LOCK                                                    L" - DXE SMM Ready To Lock - "
#define TEST_POINT_READY_TO_BOOT                                                            L" - Ready To Boot - "
#define TEST_POINT_EXIT_BOOT_SERVICES                                                       L" - Exit Boot Services - "

#define TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED                            BIT0
#define TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED                           BIT1
#define TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM                           BIT2
#define TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL                               BIT3
#define TEST_POINT_BYTE3_END_OF_DXE_DMA_PROTECTION_ENABLED                                  BIT4
#define   TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED_ERROR_CODE                    L"0x03000000"
#define   TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED_ERROR_STRING                  L"Invalid PCI Resource\r\n"
#define   TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED_ERROR_CODE                   L"0x03010000"
#define   TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED_ERROR_STRING                 L"PCI Bus Master Enabled\r\n"
#define   TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM_ERROR_CODE                   L"0x03020000"
#define   TEST_POINT_BYTE3_END_OF_DXE_NO_THIRD_PARTY_PCI_OPTION_ROM_ERROR_STRING                 L"Third Party Option ROM dispatched\r\n"
#define   TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL_ERROR_CODE                       L"0x03030000"
#define   TEST_POINT_BYTE3_END_OF_DXE_DMA_ACPI_TABLE_FUNCTIONAL_ERROR_STRING                     L"No DMA ACPI table\r\n"
#define   TEST_POINT_BYTE3_END_OF_DXE_DMA_PROTECTION_ENABLED_ERROR_CODE                          L"0x03040000"
#define   TEST_POINT_BYTE3_END_OF_DXE_DXE_DMA_PROTECTION_ENABLED_ERROR_STRING                    L"DMA protection disabled\r\n"

#define TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL                   BIT0
#define TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL               BIT1
#define TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL                        BIT2
#define TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL                     BIT3
#define TEST_POINT_BYTE4_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL                                BIT4
#define   TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL_ERROR_CODE           L"0x04000000"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_MEMORY_TYPE_INFORMATION_FUNCTIONAL_ERROR_STRING         L"Invalid Memory Type Information\r\n"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_CODE       L"0x04010000"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_STRING     L"Invalid Memory Attribute Table\r\n"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL_ERROR_CODE                L"0x04020000"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_BOOT_VARIABLE_FUNCTIONAL_ERROR_STRING              L"Invalid Boot Variable\r\n"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL_ERROR_CODE             L"0x04030000"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_UEFI_CONSOLE_VARIABLE_FUNCTIONAL_ERROR_STRING           L"Invalid Console Variable\r\n"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL_ERROR_CODE                        L"0x03040000"
#define   TEST_POINT_BYTE4_READY_TO_BOOT_ACPI_TABLE_FUNCTIONAL_ERROR_STRING                      L"Invalid ACPI Table\r\n"

#define TEST_POINT_BYTE5_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED                             BIT0
#define TEST_POINT_BYTE5_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED                            BIT1
#define TEST_POINT_BYTE5_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED                             BIT2
#define TEST_POINT_BYTE5_READY_TO_BOOT_TCG_MOR_ENABLED                                      BIT3
#define   TEST_POINT_BYTE5_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED_ERROR_CODE                     L"0x05000000"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_UEFI_SECURE_BOOT_ENABLED_ERROR_STRING                   L"UEFI Secure Boot Disable\r\n"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED_ERROR_CODE                    L"0x05010000"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_PI_SIGNED_FV_BOOT_ENABLED_ERROR_STRING                  L"PI Signed FV Boot Disable\r\n"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED_ERROR_CODE                     L"0x05020000"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_TCG_TRUSTED_BOOT_ENABLED_ERROR_STRING                   L"TCG Trusted Boot Disable\r\n"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_TCG_MOR_ENABLED_ERROR_CODE                              L"0x05030000"
#define   TEST_POINT_BYTE5_READY_TO_BOOT_TCG_MOR_ENABLED_ERROR_STRING                            L"TCG MOR not enabled\r\n"

// Byte 6/7 - SMM
#define TEST_POINT_SMM_END_OF_DXE                                                           L" - SMM End Of DXE - "
#define TEST_POINT_SMM_READY_TO_LOCK                                                        L" - SMM Ready To Lock - "
#define TEST_POINT_SMM_READY_TO_BOOT                                                        L" - SMM Ready To Boot - "
#define TEST_POINT_SMM_EXIT_BOOT_SERVICES                                                   L" - SMM Exit Boot Services - "

#define TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL                                     BIT0
#define TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL            BIT1
#define TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER                  BIT2
#define TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION                        BIT3
#define   TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL_ERROR_CODE                             L"0x06000000"
#define   TEST_POINT_BYTE6_SMM_END_OF_DXE_SMRR_FUNCTIONAL_ERROR_STRING                           L"Invalid SMRR\r\n"
#define   TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_CODE    L"0x06010000"
#define   TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_STRING  L"Invalid SMM Memory Attribute Table\r\n"
#define   TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER_ERROR_CODE          L"0x06020000"
#define   TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SECURE_SMM_COMMUNICATION_BUFFER_ERROR_STRING        L"Unsecure SMM communication buffer\r\n"
#define   TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION_ERROR_CODE                L"0x06030000"
#define   TEST_POINT_BYTE6_SMM_READY_TO_BOOT_SMM_PAGE_LEVEL_PROTECTION_ERROR_STRING              L"SMM page level protection disabled\r\n"

#define TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED                                BIT0
#define TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL                        BIT1
#define TEST_POINT_BYTE7_DXE_SMM_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT                       BIT2
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED_ERROR_CODE                        L"0x07000000"
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_SMRAM_ALIGNED_ERROR_STRING                      L"Invalid SMRAM Information\r\n"
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL_ERROR_CODE                L"0x07010000"
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_LOCK_WSMT_TABLE_FUNCTIONAL_ERROR_STRING              L"No WSMT table\r\n"
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT_ERROR_CODE               L"0x07020000"
#define   TEST_POINT_BYTE7_DXE_SMM_READY_TO_BOOT_SMI_HANDLER_INSTRUMENT_ERROR_STRING             L"No SMI Instrument\r\n"

// Byte 8 - Advanced
#define TEST_POINT_BYTE8_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL                                BIT0
#define TEST_POINT_BYTE8_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL                                BIT1
#define   TEST_POINT_BYTE8_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL_ERROR_CODE                        L"0x08000000"
#define   TEST_POINT_BYTE8_READY_TO_BOOT_ESRT_TABLE_FUNCTIONAL_ERROR_STRING                      L"No ESRT\r\n"
#define   TEST_POINT_BYTE8_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL_ERROR_CODE                        L"0x08010000"
#define   TEST_POINT_BYTE8_READY_TO_BOOT_HSTI_TABLE_FUNCTIONAL_ERROR_STRING                      L"No HSTI\r\n"

#pragma pack (1)

typedef struct {
  UINT32  Version;
  UINT32  Role;
  CHAR16  ImplementationID[256];
  UINT32  FeaturesSize;
  UINT8   FeaturesImplemented[TEST_POINT_FEATURE_SIZE];
  UINT8   FeaturesVerified[TEST_POINT_FEATURE_SIZE];
  CHAR16  End;
} ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT;

#pragma pack ()

#endif
