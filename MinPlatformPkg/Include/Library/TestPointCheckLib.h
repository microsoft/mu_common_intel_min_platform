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

EFI_STATUS
EFIAPI
TestPointTempMemoryInitDone (
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
TestPointMemoryDiscovered (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfPei (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointPciEnumerationDone (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointEndOfDxe (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLock (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointReadyToBoot (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointExitBootServices (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmEndOfDxe (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmReadyToLock (
  VOID
  );

EFI_STATUS
EFIAPI
TestPointSmmReadyToBoot (
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

#define TEST_POINT_IMPLEMENTATION_ID_PLATFORM     L"Intel MinPlatform TestPoint"

#define TEST_POINT_FEATURE_SIZE        4

#define TEST_POINT_ERROR                                                                    L"Error "
#define TEST_POINT_PLATFORM_TEST_POINT                                                      L" Platform TestPoint"

// Byte 0 - SEC
#define TEST_POINT_TEMP_MEMORY_INIT_DONE                                                     L" - Temp Memory Init Done - "

#define TEST_POINT_BYTE0_TEMP_INIT_DONE                                                     BIT0
#define      TEST_POINT_BYTE0_TEMP_MEMORY_INIT_DONE_ERROR_CODE_1                            L"0x00000001"
#define      TEST_POINT_BYTE0_TEMP_MEMORY_INIT_DONE_ERROR_STRING_1                          L"Invalid Temp Ram\r\n"

// Byte 1 - PEI
#define TEST_POINT_DEBUG_INIT_DONE                                                          L" - Debug Init Done - "
#define TEST_POINT_MEMORY_DISCOVERED                                                        L" - Memory Discovered - "
#define TEST_POINT_END_OF_PEI                                                               L" - End Of PEI - "

#define TEST_POINT_BYTE1_DEBUG_INIT_DONE                                                    BIT0
#define TEST_POINT_BYTE1_MEMORY_DISCOVERED                                                  BIT1
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_CODE_1                                L"0x01010001"
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_STRING_1                              L"Invalid Memory Resource\r\n"
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_CODE_2                                L"0x01010002"
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_STRING_2                              L"Invalid MTRR Setting\r\n"
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_CODE_3                                L"0x01010002"
#define      TEST_POINT_BYTE1_MEMORY_DISCOVERED_ERROR_STRING_3                              L"Invalid SMRAM Resource\r\n"
#define TEST_POINT_BYTE1_END_OF_PEI                                                         BIT2
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_1                                       L"0x01020001"
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_1                                     L"Invalid System Resource\r\n"
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_2                                       L"0x01020002"
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_2                                     L"Invalid MTRR Setting\r\n"
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_3                                       L"0x01010003"
#define      TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_3                                     L"Invalid FV Information\r\n"

// Byte 2 - DXE
#define TEST_POINT_PCI_ENUMERATION_DONE                                                     L" - PCI Enumeration Done - "
#define TEST_POINT_END_OF_DXE                                                               L" - End Of DXE - "
#define TEST_POINT_DXE_SMM_READY_TO_LOCK                                                    L" - DXE SMM Ready To Lock - "
#define TEST_POINT_READY_TO_BOOT                                                            L" - Ready To Boot - "
#define TEST_POINT_EXIT_BOOT_SERVICES                                                       L" - Exit Boot Services - "

#define TEST_POINT_BYTE2_PCI_ENUMERATION_DONE                                               BIT0
#define      TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_ERROR_CODE_1                             L"0x02010001"
#define      TEST_POINT_BYTE2_PCI_ENUMERATION_DONE_ERROR_STRING_1                           L"Invalid PCI Resource\r\n"
#define TEST_POINT_BYTE2_END_OF_DXE                                                         BIT1
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_CODE_1                                       L"0x02020001"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_STRING_1                                     L"Invalid PCI OROM\r\n"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_CODE_2                                       L"0x02020002"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_STRING_2                                     L"Invalid Memory Map\r\n"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_CODE_3                                       L"0x02020003"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_STRING_3                                     L"Invalid GCD Map\r\n"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_CODE_4                                       L"0x02020004"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_STRING_4                                     L"Invalid Console Variable\r\n"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_CODE_5                                       L"0x02020005"
#define      TEST_POINT_BYTE2_END_OF_DXE_ERROR_STRING_5                                     L"Invalid Boot Variable\r\n"
#define TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK                                              BIT2
#define      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_ERROR_CODE_1                            L"0x02040001"
#define      TEST_POINT_BYTE2_DXE_SMM_READY_TO_LOCK_ERROR_STRING_1                          L"Invalid SMRAM Information\r\n"
#define TEST_POINT_BYTE2_READY_TO_BOOT                                                      BIT3
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_1                                    L"0x02080001"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_1                                  L"Invalid Device\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_2                                    L"0x02080002"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_2                                  L"Invalid Memory Type Information\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_3                                    L"0x02080003"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_3                                  L"Invalid UEFI Variable\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_4                                    L"0x02080004"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_4                                  L"Invalid Memory Attribute Table\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_5                                    L"0x02080005"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_5                                  L"Invalid ACPI Table\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_6                                    L"0x02080006"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_6                                  L"Invalid WSMT Table\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_7                                    L"0x02080007"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_7                                  L"Invalid DMAR Table\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_8                                    L"0x02080008"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_8                                  L"Invalid HSTI\r\n"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_9                                    L"0x02080009"
#define      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_9                                  L"Invalid ESRT\r\n"
#define TEST_POINT_BYTE2_EXIT_BOOT_SERVICES                                                 BIT4

// Byte 3 - SMM
#define TEST_POINT_SMM_END_OF_DXE                                                           L" - SMM End Of DXE - "
#define TEST_POINT_SMM_READY_TO_LOCK                                                        L" - SMM Ready To Lock - "
#define TEST_POINT_SMM_READY_TO_BOOT                                                        L" - SMM Ready To Boot - "
#define TEST_POINT_SMM_EXIT_BOOT_SERVICES                                                   L" - SMM Exit Boot Services - "

#define TEST_POINT_BYTE3_SMM_END_OF_DXE                                                     BIT0
#define      TEST_POINT_BYTE3_SMM_END_OF_DXE_ERROR_CODE_1                                   L"0x03010001"
#define      TEST_POINT_BYTE3_SMM_END_OF_DXE_ERROR_STRING_1                                 L"Invalid SMM Image\r\n"
#define TEST_POINT_BYTE3_SMM_READY_TO_LOCK                                                  BIT1
#define      TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_CODE_1                                L"0x03020001"
#define      TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_STRING_1                              L"Invalid SMM Memory Attribute Table\r\n"
#define      TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_CODE_2                                L"0x03020002"
#define      TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_STRING_2                              L"Invalid SMRR\r\n"
#define TEST_POINT_BYTE3_SMM_READY_TO_BOOT                                                  BIT2
#define TEST_POINT_BYTE3_SMM_EXIT_BOOT_SERVICES                                             BIT3

#pragma pack (1)

typedef struct {
  UINT32  Version;
  UINT32  Role;
  CHAR16  ImplementationID[256];
  UINT32  FeaturesSize;
  UINT8   FeaturesRequired[TEST_POINT_FEATURE_SIZE];
  UINT8   FeaturesImplemented[TEST_POINT_FEATURE_SIZE];
  UINT8   FeaturesVerified[TEST_POINT_FEATURE_SIZE];
  CHAR16  End;
} ADAPTER_INFO_PLATFORM_TEST_POINT_STRUCT;

#pragma pack ()

#endif
