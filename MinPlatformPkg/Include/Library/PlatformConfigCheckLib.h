/** @file

  Platform configuration check library for TestPointCheckLib

  Copyright (c) Microsoft Corporation. All rights reserved

**/

#ifndef _PLATFORM_CONFIG_CHECK_LIB_H_
#define _PLATFORM_CONFIG_CHECK_LIB_H_

#include <Uefi.h>

/**
  This function dumps platform level information at Exit Boot Services.

  @retval     EFI_SUCCESS  Function has completed successfully.
              Other        Function error indicates failure.
**/
EFI_STATUS
EFIAPI
PlatformConfigDumpExitBootServices (
  VOID
  );

#endif // _PLATFORM_CONFIG_CHECK_LIB_H_
