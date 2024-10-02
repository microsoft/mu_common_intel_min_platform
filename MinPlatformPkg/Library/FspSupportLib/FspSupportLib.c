/** @file FspSupportLib.c

  Library to report FSP support state

  Copyright (c) Microsoft Corporation. All rights reserved.

**/

#include <Uefi.h>

#include <Library/FspSupportLib.h>
#include <Library/PcdLib.h>

/**
  Return if platform is boot in FSP wrapper enabled

  @retval     TRUE  FSP binary is used.
              FALSE FSP binary is not used.
**/
BOOLEAN
EFIAPI
FspGetWrapperBootMode (
  VOID
  )
{
  return PcdGetBool (PcdFspWrapperBootMode);
}

/**
  Return FSP mode selection. Only valid on certain platforms

  @retval  FSP mode.
**/
UINT8
EFIAPI
FspGetModeSelection (
  VOID
  )
{
  return PcdGet8 (PcdFspModeSelection);
}
