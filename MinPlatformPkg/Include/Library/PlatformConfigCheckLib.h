/** @file
  Platform configuration check and information dump library implementation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

  Copyright (c) Microsoft Corporation. All rights reserved.

  MU_CHANGE [NEW FILE] - Support platform level configuration testing

**/

#ifndef _PLATFORM_CONFIG_CHECK_LIB_H_
#define _PLATFORM_CONFIG_CHECK_LIB_H_

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
