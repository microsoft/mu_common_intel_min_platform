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
#include <Library/UefiBootServicesTableLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/MemoryAttributesTable.h>

CHAR8 *
ShortNameOfMemoryType(
  IN UINT32 Type
  );

VOID
DumpMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  )
{
  UINTN                 Index;
  EFI_MEMORY_DESCRIPTOR *Entry;
  UINT64                Pages[EfiMaxMemoryType];

  ZeroMem (Pages, sizeof(Pages));

  DEBUG ((DEBUG_INFO, "MemoryAttributesTable:"));
  DEBUG ((DEBUG_INFO, " Version=0x%x", MemoryAttributesTable->Version));
  DEBUG ((DEBUG_INFO, " Count=0x%x", MemoryAttributesTable->NumberOfEntries));
  DEBUG ((DEBUG_INFO, " DescriptorSize=0x%x\n", MemoryAttributesTable->DescriptorSize));
  Entry = (EFI_MEMORY_DESCRIPTOR *)(MemoryAttributesTable + 1);
  DEBUG ((DEBUG_INFO, "Type       Start            End              # Pages          Attributes\n"));
  for (Index = 0; Index < MemoryAttributesTable->NumberOfEntries; Index++) {
    DEBUG ((DEBUG_INFO, ShortNameOfMemoryType(Entry->Type)));
    DEBUG ((DEBUG_INFO, " %016LX-%016LX %016LX %016LX\n",
      Entry->PhysicalStart,
      Entry->PhysicalStart+MultU64x64 (SIZE_4KB,Entry->NumberOfPages) - 1,
      Entry->NumberOfPages,
      Entry->Attribute
      ));
    if (Entry->Type < EfiMaxMemoryType) {
      Pages[Entry->Type] += Entry->NumberOfPages;
    }
    Entry = NEXT_MEMORY_DESCRIPTOR (Entry, MemoryAttributesTable->DescriptorSize);
  }
  
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "  RT_Code   : %14ld Pages (%ld Bytes)\n", Pages[EfiRuntimeServicesCode],     MultU64x64(SIZE_4KB, Pages[EfiRuntimeServicesCode])));
  DEBUG ((DEBUG_INFO, "  RT_Data   : %14ld Pages (%ld Bytes)\n", Pages[EfiRuntimeServicesData],     MultU64x64(SIZE_4KB, Pages[EfiRuntimeServicesData])));
  DEBUG ((DEBUG_INFO, "              -------------- \n"));
}

EFI_STATUS
TestPointDumpMemAttribute (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *MemoryAttributesTable;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpMemAttribute - Enter\n"));
  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, &MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    DumpMemoryAttributesTable(MemoryAttributesTable);
  } else {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_CODE_4 TEST_POINT_READY_TO_BOOT TEST_POINT_BYTE2_READY_TO_BOOT_ERROR_STRING_4
      );
  }
  DEBUG ((DEBUG_INFO, "==== TestPointDumpMemAttribute - Exit\n"));

  return Status;
}
