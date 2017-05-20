/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiSmm.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmMemoryAttributesTable.h>

VOID
DumpMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  );

/**
  Retrieves a pointer to the system configuration table from the SMM System Table
  based on a specified GUID.

  @param[in]   TableGuid       The pointer to table's GUID type.
  @param[out]  Table           The pointer to the table associated with TableGuid in the EFI System Table.

  @retval EFI_SUCCESS     A configuration table matching TableGuid was found.
  @retval EFI_NOT_FOUND   A configuration table matching TableGuid could not be found.

**/
EFI_STATUS
EFIAPI
SmmGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  )
{
  UINTN             Index;

  ASSERT (TableGuid != NULL);
  ASSERT (Table != NULL);

  *Table = NULL;
  for (Index = 0; Index < gSmst->NumberOfTableEntries; Index++) {
    if (CompareGuid (TableGuid, &(gSmst->SmmConfigurationTable[Index].VendorGuid))) {
      *Table = gSmst->SmmConfigurationTable[Index].VendorTable;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
TestPointDumpSmmMemAttribute (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *MemoryAttributesTable;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmmMemAttribute - Enter\n"));
  Status = SmmGetSystemConfigurationTable (&gEdkiiPiSmmMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    DumpMemoryAttributesTable((EFI_MEMORY_ATTRIBUTES_TABLE *)MemoryAttributesTable);
  } else {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_CODE_1 TEST_POINT_SMM_READY_TO_LOCK TEST_POINT_BYTE2_SMM_READY_TO_LOCK_ERROR_STRING_1
      );
  }
  DEBUG ((DEBUG_INFO, "==== TestPointDumpSmmMemAttribute - Exit\n"));

  return Status;
}
