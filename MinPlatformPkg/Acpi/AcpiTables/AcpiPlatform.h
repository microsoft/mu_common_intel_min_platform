/** @file
  This is an implementation of the ACPI platform driver.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _ACPI_PLATFORM_H_
#define _ACPI_PLATFORM_H_

//
// Statements that include other header files
//

#include <Base.h>
#include <Uefi.h>
#include <IndustryStandard/Pci30.h>
#include <IndustryStandard/Acpi.h>
#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Library/BoardAcpiTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/AslUpdateLib.h>

#include <Protocol/AcpiTable.h>
#include <Protocol/MpService.h>
#include <Protocol/PciIo.h>

#include <Register/Cpuid.h>

#include "Fadt/Fadt.h"
#include "Facs/Facs.h"
#include "Madt/Madt.h"
#include "Mcfg/Mcfg.h"
#include "Hpet/Hpet.h"
#include "Wsmt/Wsmt.h"

//
// ACPI table information used to initialize tables.
//
#define EFI_ACPI_OEM_ID                       "INTEL "
#define ACPI_OEM_TABLE_ID_SKL                 0x4C4B53           // SKL
#define ACPI_OEM_TABLE_ID_SKL_ULT             0x544C552D4C4B53   // SKL-ULT
#define ACPI_OEM_TABLE_ID_SKL_SDS             0x5344532D4C4B53   // SKL-SDS
#define ACPI_OEM_TABLE_ID_KBL                 0x4C424B           // KBL
#define ACPI_OEM_TABLE_ID_KBL_ULT             0x544C552D4C424B   // KBL-ULT
#define ACPI_OEM_TABLE_ID_KBL_SDS             0x5344532D4C424B   // KBL-SDS
#define ACPI_OEM_TABLE_ID_UNKNOWN             0x304E574F4E4B4E55 // "UNKNOWN0"
#define EFI_ACPI_OEM_REVISION                 0x00000001
#define EFI_ACPI_CREATOR_ID                   0x5446534D         // "MSFT"
#define EFI_ACPI_CREATOR_REVISION             0x00000005F

#define MAX_CPU_NUM               16

typedef struct {
  UINT8   ApicId;
  UINT32  Flags;
  UINT8   Package;
  UINT8   Die;
  UINT8   Core;
  UINT8   Thread;
} EFI_CPU_ID_ORDER_MAP;

typedef struct {
  UINT8   Package;
  UINT8   ApicId;
  UINT32  Flags;
} EFI_CPU_APIC_ID_REORDER_MAP;

typedef struct {
  UINT8   BspApicId;
  UINT8   TotalThreads;
  UINT8   PackageNo;
  UINT8   CoreNo;
  UINT8   LogicalThreadNo;
} EFI_CPU_PACKAGE_INFO;

//
// Function definitions
//

/**
  Entry point of the ACPI platform driver.

  @param[in] ImageHandle  A handle for the image that is initializing this driver
  @param[in] SystemTable  A pointer to the EFI system table

  @retval    EFI_SUCCESS  The driver installed without error.
  @retval    EFI_ABORTED  The driver encountered an error and could not complete
                          installation of the ACPI tables.
**/
EFI_STATUS
EFIAPI
InstallAcpiPlatform (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  );

EFI_STATUS
SortCpuLocalApicInTable (
  IN  EFI_MP_SERVICES_PROTOCOL                   *MpService,
  IN  UINTN                                      NumberOfCPUs,
  IN  UINTN                                      NumberOfEnabledCPUs
  );

EFI_STATUS
AppendCpuMapTableEntry (
  IN  EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE   *AcpiLocalApic,
  IN  UINTN                                      NumberOfCPUs,
  IN  UINTN                                      NumberOfEnabledCPUs,
  IN  UINT8                                      LocalApicCounter
  );

#endif
