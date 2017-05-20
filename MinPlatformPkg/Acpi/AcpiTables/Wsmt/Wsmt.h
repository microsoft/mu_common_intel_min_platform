/** @file
  ACPI WSMT table

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _WSMT_H_
#define _WSMT_H_

#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/WindowsSmmSecurityMitigationTable.h>
#include <Library/PcdLib.h>

//
// WSMT Definitions
//

#define EFI_ACPI_OEM_WSMT_REVISION                      0x00000001

extern EFI_ACPI_WSMT_TABLE Wsmt;

#endif
