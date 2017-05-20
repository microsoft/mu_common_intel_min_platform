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
#include <IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h>
#include <IndustryStandard/HighPrecisionEventTimerTable.h>
#include <IndustryStandard/DmaRemappingReportingTable.h>
#include <IndustryStandard/WindowsSmmSecurityMitigationTable.h>
#include <Guid/Acpi.h>

BOOLEAN  mDmarFound = FALSE;
BOOLEAN  mWsmtFound = FALSE;

EFI_STATUS
DumpAcpiMadt (
  IN EFI_ACPI_4_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER  *Madt
  );

EFI_STATUS
DumpAcpiMcfg (
  IN EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER  *Mcfg
  );

EFI_STATUS
DumpAcpiHpet (
  IN EFI_ACPI_HIGH_PRECISION_EVENT_TIMER_TABLE_HEADER  *Hpet
  );

EFI_STATUS
DumpAcpiDmar (
  IN EFI_ACPI_DMAR_HEADER  *Dmar
  );

EFI_STATUS
DumpAcpiWsmt (
  IN EFI_ACPI_WSMT_TABLE  *Wsmt
  );

VOID
DumpCharArray (
  IN CHAR8  *Ch,
  IN UINTN  Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; Index++) {
    DEBUG ((DEBUG_INFO, "%c", Ch[Index]));
  }
}

VOID
DumpAcpiTableHeader (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Table
  )
{
  DEBUG ((DEBUG_INFO, "  "));
  DumpCharArray ((CHAR8 *)&Table->Signature, sizeof(Table->Signature));
  DEBUG ((DEBUG_INFO, "  : (0x%016lx) 0x%02x \'", Table, Table->Revision));
  DumpCharArray (Table->OemId, sizeof(Table->OemId));
  DEBUG ((DEBUG_INFO, "\' \'"));
  DumpCharArray ((CHAR8 *)&Table->OemTableId, sizeof(Table->OemTableId));
  DEBUG ((DEBUG_INFO, "\' 0x%08x \'", Table->OemRevision));
  DumpCharArray ((CHAR8 *)&Table->CreatorId, sizeof(Table->CreatorId));
  DEBUG ((DEBUG_INFO, "\' 0x%08x |\n", Table->CreatorRevision));
}

EFI_STATUS
DumpAcpiFadt (
  IN EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE  *Fadt
  )
{
  DumpAcpiTableHeader (&Fadt->Header);
  DEBUG ((DEBUG_INFO, "         "));
  DEBUG ((DEBUG_INFO, " SCI=0x%04x", Fadt->SciInt));
  DEBUG ((DEBUG_INFO, " SMI=0x%08x", Fadt->SmiCmd));
  DEBUG ((DEBUG_INFO, " AcpiEnable=0x%02x", Fadt->AcpiEnable));
  DEBUG ((DEBUG_INFO, " AcpiDisable=0x%02x", Fadt->AcpiDisable));
  DEBUG ((DEBUG_INFO, "\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
DumpAcpiFacs (
  IN EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE  *Facs
  )
{
  DEBUG ((DEBUG_INFO, "  "));
  DumpCharArray ((CHAR8 *)&Facs->Signature, sizeof(Facs->Signature));
  DEBUG ((DEBUG_INFO, "  : (0x%016lx) 0x%02x\n", Facs, Facs->Version));
  DEBUG ((DEBUG_INFO, "    "));
  DEBUG ((DEBUG_INFO, " HardwareSignature=%08x\n", Facs->HardwareSignature));
  return EFI_SUCCESS;
}

EFI_STATUS
DumpAcpiTable (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Table
  )
{
  EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE  *Fadt;
  EFI_STATUS                                 Status;
  
  if (Table == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  switch (Table->Signature) {
  case EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE:
    Fadt = (EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)Table;
    Status = DumpAcpiFadt (Fadt);
    if (Fadt->Header.Revision >= EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
      if (Fadt->XFirmwareCtrl != 0) {
        DumpAcpiFacs ((EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE *)(UINTN)Fadt->XFirmwareCtrl);
      } else {
        DumpAcpiFacs ((EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE *)(UINTN)Fadt->FirmwareCtrl);
      }
      if (Fadt->XDsdt != 0) {
        DumpAcpiTable ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Fadt->XDsdt);
      } else {
        DumpAcpiTable ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Fadt->Dsdt);
      }
    } else {
      DumpAcpiFacs ((EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE *)(UINTN)Fadt->FirmwareCtrl);
      DumpAcpiTable ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Fadt->Dsdt);
    }
    return Status;
  case EFI_ACPI_4_0_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE:
    Status = DumpAcpiMadt ((EFI_ACPI_4_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER *)Table);
    return Status;
  case EFI_ACPI_2_0_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_SIGNATURE:
    Status = DumpAcpiMcfg ((EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *)Table);
    return Status;
  case EFI_ACPI_3_0_HIGH_PRECISION_EVENT_TIMER_TABLE_SIGNATURE:
    Status = DumpAcpiHpet ((EFI_ACPI_HIGH_PRECISION_EVENT_TIMER_TABLE_HEADER *)Table);
    return Status;
  case EFI_ACPI_4_0_DMA_REMAPPING_TABLE_SIGNATURE:
    Status = DumpAcpiDmar ((EFI_ACPI_DMAR_HEADER *)Table);
    mDmarFound = TRUE;
    return Status;
  case EFI_ACPI_WINDOWS_SMM_SECURITY_MITIGATION_TABLE_SIGNATURE:
    Status = DumpAcpiWsmt ((EFI_ACPI_WSMT_TABLE *)Table);
    mWsmtFound = TRUE;
    return Status;
  default:
    break;
  }
  DumpAcpiTableHeader (Table);
  return EFI_SUCCESS;
}

EFI_STATUS
DumpAcpiRsdt (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Rsdt
  )
{
  EFI_STATUS                         Status;
  UINTN                              Index;
  UINT32                             EntryCount;
  UINT32                             *EntryPtr;
  EFI_ACPI_DESCRIPTION_HEADER        *Table;
  BOOLEAN                            Result;

  if (Rsdt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EntryCount = (Rsdt->Length - sizeof (EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT32);
  EntryPtr = (UINT32 *)(Rsdt + 1);
  Result = TRUE;
  for (Index = 0; Index < EntryCount; Index ++, EntryPtr ++) {
    Table = (EFI_ACPI_DESCRIPTION_HEADER *)((UINTN)(*EntryPtr));
    Status = DumpAcpiTable (Table);
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    }
  }
  if (!Result) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
DumpAcpiXsdt (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Xsdt
  )
{
  EFI_STATUS                     Status;
  UINTN                          Index;
  UINT32                         EntryCount;
  UINT64                         EntryPtr;
  UINTN                          BasePtr;
  EFI_ACPI_DESCRIPTION_HEADER    *Table;
  BOOLEAN                        Result;

  if (Xsdt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EntryCount = (Xsdt->Length - sizeof (EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT64);
  
  BasePtr = (UINTN)(Xsdt + 1);
  Result = TRUE;
  for (Index = 0; Index < EntryCount; Index ++) {
    CopyMem (&EntryPtr, (VOID *)(BasePtr + Index * sizeof(UINT64)), sizeof(UINT64));
    Table = (EFI_ACPI_DESCRIPTION_HEADER *)((UINTN)(EntryPtr));
    Status = DumpAcpiTable (Table);
    if (EFI_ERROR(Status)) {
      Result = FALSE;
    }
  }
  if (!Result) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
DumpAcpiRsdp (
  IN EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER  *Rsdp
  )
{
  EFI_STATUS                                    Status;
  EFI_ACPI_DESCRIPTION_HEADER                   *Rsdt;
  EFI_ACPI_DESCRIPTION_HEADER                   *Xsdt;

  DumpCharArray ((CHAR8 *)&Rsdp->Signature, sizeof(Rsdp->Signature));
  DEBUG ((DEBUG_INFO, ": (0x%016lx) 0x%02x \'", Rsdp, Rsdp->Revision));
  DumpCharArray (Rsdp->OemId, sizeof(Rsdp->OemId));
  DEBUG ((DEBUG_INFO, "\'\n"));
  DEBUG ((DEBUG_INFO, "         "));
  DEBUG ((DEBUG_INFO, " RSDT=0x%08x XSDT=0x%016lx\n", Rsdp->RsdtAddress, Rsdp->XsdtAddress));

  if (Rsdp->Revision >= EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER_REVISION) {
    DumpAcpiTable ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp->XsdtAddress);
  }
  DumpAcpiTable ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp->RsdtAddress);

  //
  // Search XSDT
  //
  if (Rsdp->Revision >= EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER_REVISION) {
    Xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN) Rsdp->XsdtAddress;
    Status = DumpAcpiXsdt (Xsdt);
  } else {
    //
    // Search RSDT
    //
    Rsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN) Rsdp->RsdtAddress;
    Status = DumpAcpiRsdt (Rsdt);
  }

  return Status;
}

EFI_STATUS
DumpAcpiWithGuid (
  IN EFI_GUID  *AcpiTableGuid
  )
{
  VOID        *Rsdp;
  EFI_STATUS  Status;

  Status = EfiGetSystemConfigurationTable (AcpiTableGuid, &Rsdp);
  if (EFI_ERROR(Status)) {
    return EFI_NOT_FOUND;
  }

  Status = DumpAcpiRsdp (Rsdp);

  return Status;
}

EFI_STATUS
TestPointDumpAcpi (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "==== TestPointDumpAcpi - Enter\n"));

  DEBUG ((DEBUG_INFO, "AcpiTable :\n"));
  DEBUG ((DEBUG_INFO, "  Table         Address        Rev   OemId   OemTableId   OemRev   Creat  CreatorRev\n"));
  Status = DumpAcpiWithGuid (&gEfiAcpi20TableGuid);
  if (Status == EFI_NOT_FOUND) {
    Status = DumpAcpiWithGuid (&gEfiAcpi10TableGuid);
  }

  DEBUG ((DEBUG_INFO, "==== TestPointDumpAcpi - Exit\n"));
  
  if (EFI_ERROR(Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_5 TEST_POINT_READY_TO_BOOT TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_5
      );
  }

  if (!mWsmtFound) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_6 TEST_POINT_READY_TO_BOOT TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_6
      );
    Status = EFI_INVALID_PARAMETER;
  }
  if (!mDmarFound) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_7 TEST_POINT_READY_TO_BOOT TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_7
      );
    Status = EFI_INVALID_PARAMETER;
  }
  
  if (!mDmarFound) {
    Status = EFI_INVALID_PARAMETER;
  }

  return Status;
}
