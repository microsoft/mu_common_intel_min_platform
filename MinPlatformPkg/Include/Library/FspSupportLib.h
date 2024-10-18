/** @file FspSupportLib.c

  Library to report FSP support state

  Copyright (c) Microsoft Corporation. All rights reserved.

**/

#ifndef _FSP_SUPPORT_LIB_H_
#define _FSP_SUPPORT_LIB_H_

/**
  Return if platform is boot in FSP wrapper enabled

  @retval     TRUE  FSP binary is used.
              FALSE FSP binary is not used.
**/
BOOLEAN
EFIAPI
FspGetWrapperBootMode (
  VOID
  );

/**
  Return FSP mode selection. Only valid on certain platforms

  @retval  FSP mode.
**/
UINT8
EFIAPI
FspGetModeSelection (
  VOID
  );

#endif // _FSP_SUPPORT_LIB_H_
