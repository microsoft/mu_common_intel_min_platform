/** @file
File that includes function prototypes used by both Traditional and
Standalone MM

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

/**
  The MM library constructor.
  The function does the necessary initialization work for this library
  instance.
  @retval     EFI_SUCCESS       The function always return EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
MmTestPointCheckLibConstructor (
  VOID
  );

#endif
