/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2022, Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiMm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Register/SmramSaveStateMap.h>
#include <Register/StmApi.h>
#include <Register/Msr.h>

EFI_STATUS
TestPointCheckStandaloneMmPaging (
  VOID
  )
{
  //TestPointCheckMmPaging ();
  // Currently unsupported by StandaloneMm
  return EFI_UNSUPPORTED;
}
