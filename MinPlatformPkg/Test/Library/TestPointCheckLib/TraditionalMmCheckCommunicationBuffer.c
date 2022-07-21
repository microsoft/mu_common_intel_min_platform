/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2022, Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiSmm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Guid/MemoryAttributesTable.h>

extern EFI_GCD_MEMORY_SPACE_DESCRIPTOR *mGcdMemoryMap;
extern EFI_GCD_IO_SPACE_DESCRIPTOR     *mGcdIoMap;
extern UINTN                           mGcdMemoryMapNumberOfDescriptors;
extern UINTN                           mGcdIoMapNumberOfDescriptors;

EFI_STATUS
TestPointCheckTraditionalMmCommunicationBuffer (
  IN EFI_MEMORY_DESCRIPTOR        *UefiMemoryMap,
  IN UINTN                        UefiMemoryMapSize,
  IN UINTN                        UefiDescriptorSize,
  IN EFI_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable
  )
{
  TestPointCheckMmCommunicationBuffer (UefiMemoryMap, UefiMemoryMapSize, UefiDescriptorSize, MemoryAttributesTable);
}
