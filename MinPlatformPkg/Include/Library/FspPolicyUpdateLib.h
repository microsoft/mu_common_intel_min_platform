/** @file
  Function prototype of FspPolicyUpdateLib.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _FSP_POLICY_UPDATE_LIB_H_
#define _FSP_POLICY_UPDATE_LIB_H_

/**
  Performs FSPM UPD Policy update.

  A platform may use this API to update the FSPM UPD policy initialized
  by the silicon module or the default UPD data.
  The output of FSPM UPD data from this API is the final UPD data.

  @param[in, out] FspmUpd       Pointer to FSPM UPD data.
**/
VOID
EFIAPI
FspmPolicyUpdate (
  IN OUT VOID    *FspmUpd
  );

/**
  Performs FSPS UPD Policy update.

  A platform may use this API to update the FSPS UPD policy initialized
  by the silicon module or the default UPD data.
  The output of FSPS UPD data from this API is the final UPD data.

  @param[in, out] FspsUpd       Pointer to FSPS UPD data.
**/
VOID
EFIAPI
FspsPolicyUpdate (
  IN OUT VOID    *FspsUpd
  );

#endif
