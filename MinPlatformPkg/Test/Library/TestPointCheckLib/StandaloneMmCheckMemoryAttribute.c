/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/MmServicesTableLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmMemoryAttributesTable.h>
#include <Protocol/LoadedImage.h>

VOID
TestPointDumpMemoryAttributesTable (
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
TestPointCheckStandaloneMmMemAttribute (
  VOID
  )
{
  // Unsupported by current implementation of Standalone MM
  return EFI_UNSUPPORTED;
}
