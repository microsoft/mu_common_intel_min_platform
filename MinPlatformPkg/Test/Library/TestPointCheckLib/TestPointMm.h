/** @file

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_POINT_MM_H_
#define _TEST_POINT_MM_H_

#include <Uefi.h>
#include <PiSmm.h>
#include <Library/TestPointCheckLib.h>
#include <Library/DebugLib.h>

/**
  Wrapper function for checking the MM communication buffer
**/
EFI_STATUS
EFIAPI
TestPointReadyToLockSecureMmCommunicationBuffer (
  VOID
  );

/**
  Wrapper function for MM Page Protection
**/
EFI_STATUS
EFIAPI
TestPointReadyToBootMmPageProtection (
  VOID
  );

/**
  Wrapper function for Memory Attribute table checking
**/
EFI_STATUS
EFIAPI
TestPointReadyToLockMmMemoryAttributeTableFunctional (
  VOID
  );

/**
  Wrapper function for the MM Page Protection Handler
**/
EFI_STATUS
TestPointReadyToBootMmPageProtectionHandler (
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  );

#endif