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
TestPointTempMemoryInitDone (
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
TestPointMemoryDiscovered (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfPei (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointPciEnumerationDone (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointEndOfDxe (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointDxeSmmReadyToLock (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointReadyToBoots (
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
TestPointSmmEndOfDxe (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToLock (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TestPointSmmReadyToBoot (
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
