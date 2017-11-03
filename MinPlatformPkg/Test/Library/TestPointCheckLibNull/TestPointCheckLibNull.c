/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/TestPointCheckLib.h>

EFI_STATUS
EFIAPI
TestPointTempMemoryFunction (
  IN VOID   *TempRamStart,
  IN VOID   *TempRamEnd
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDebugInitDone (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMtrrFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredMemoryResourceFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointMemoryDiscoveredFvInfoFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiSystemResourceFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiMtrrFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPeiPciBusMasterDisabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciBusMasterDisabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointPciEnumerationDonePciResourceAllocated (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxeNoThirdPartyPciOptionRom (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxeDmarTableFuntional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockSmramAligned (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLockWsmtTableFuntional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToBootSmmPageProtection (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootSmiHandlerInstrument (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootAcpiTableFuntional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootMemoryTypeInformationFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiMemoryAttributeTableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiBootVariableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiConsoleVariableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootHstiTableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootEsrtTableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootUefiSecureBootEnabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootPiSignedFvBootEnabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgTrustedBootEnabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBootTcgMorEnabled (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointExitBootServices (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmEndOfDxeSmrrFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSmmMemoryAttributeTableFunctional (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLockSecureSmmCommunicationBuffer (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToBootSmmPageProtection (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmExitBootServices (
  VOID
  )
{
  return EFI_SUCCESS;
}
