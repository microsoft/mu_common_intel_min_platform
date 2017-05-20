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
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>

CHAR16  *mLoadOptionVariableList[] = {
  L"Boot",
  L"Driver",
  L"SysPrep",
};

CHAR16  *mPlatformRecoveryOptionVariableList[] = {
  L"PlatformRecovery", // does not have PlatformRecoveryOrder
};

CHAR16  *mOsRecoveryOptionVariableList[] = {
  L"OsRecovery", // VariableGuid in OsRecoveryOrder
};

CHAR16  *mKeyOptionVariableList[] = {
  L"Key", // does not have KeyOrder
};

VOID
DumpLoadOption (
  IN CHAR16           *OptionName,
  IN EFI_LOAD_OPTION  *LoadOption,
  IN UINTN            Size
  )
{
  CHAR16                        *Str;
  CHAR16                        *Description;
  EFI_DEVICE_PATH_PROTOCOL      *FilePathList;

  if (LoadOption == NULL) {
    DEBUG ((DEBUG_INFO, "%s: <NULL>\n", OptionName));
    return ;
  }

  Description = (CHAR16 *)(LoadOption + 1);

  FilePathList = (EFI_DEVICE_PATH_PROTOCOL *)((UINTN)Description + StrSize (Description));

  DEBUG ((DEBUG_INFO, "%s: [0x%08x] \"%s\"", OptionName, LoadOption->Attributes, Description));
  Str = ConvertDevicePathToText(FilePathList, TRUE, TRUE);
  DEBUG ((DEBUG_INFO, " %s\n", Str));
  if (Str != NULL) {
    FreePool (Str);
  }
}

VOID
DumpKeyOption (
  IN CHAR16           *OptionName,
  IN EFI_KEY_OPTION   *KeyOption,
  IN UINTN            Size
  )
{
  UINTN               Index;
  EFI_INPUT_KEY       *Keys;

  Keys = (EFI_INPUT_KEY *)(KeyOption + 1);

  DEBUG ((DEBUG_INFO, "%s: [Boot%04x] 0x%08x", OptionName, KeyOption->BootOption, KeyOption->KeyData.PackedValue));
  for (Index = 0; Index < KeyOption->KeyData.Options.InputKeyCount; Index++) {
    DEBUG ((DEBUG_INFO, " (%04x/%04x)", Keys[Index].ScanCode, Keys[Index].UnicodeChar));
  }
  DEBUG ((DEBUG_INFO, "\n"));
}

VOID
DumpLoadOptionVariable (
  VOID
  )
{
  UINT16      *BootOrder;
  UINTN       OrderSize;
  VOID        *Variable;
  UINTN       ListIndex;
  UINTN       Size;
  UINTN       Index;
  EFI_STATUS  Status;
  CHAR16      BootOptionName[sizeof(L"PlatformRecovery####")];
  CHAR16      BootOrderName[sizeof(L"PlatformRecoveryOrder")];

  for (ListIndex = 0; ListIndex < sizeof(mLoadOptionVariableList)/sizeof(mLoadOptionVariableList[0]); ListIndex++) {
    UnicodeSPrint (BootOrderName, sizeof(BootOrderName), L"%sOrder", mLoadOptionVariableList[ListIndex]);
    Status = GetVariable2 (BootOrderName, &gEfiGlobalVariableGuid, &BootOrder, &OrderSize);
    if (EFI_ERROR(Status)) {
      continue;
    }
    for (Index = 0; Index < OrderSize/sizeof(CHAR16); Index++) {
      UnicodeSPrint (BootOptionName, sizeof(BootOptionName), L"%s%04x", mLoadOptionVariableList[ListIndex], BootOrder[Index]);
      Status = GetVariable2 (BootOptionName, &gEfiGlobalVariableGuid, &Variable, &Size);
      if (!EFI_ERROR(Status)) {
        DumpLoadOption (BootOptionName, Variable, Size);
      } else {
        DumpLoadOption (BootOptionName, NULL, 0);
      }
    }
  }
}

VOID
DumpPlatformRecoveryOptionVariable (
  VOID
  )
{
  VOID        *Variable;
  UINTN       ListIndex;
  UINTN       Size;
  UINTN       Index;
  EFI_STATUS  Status;
  CHAR16      PlatformRecoveryOptionName[sizeof(L"PlatformRecovery####")];

  for (ListIndex = 0; ListIndex < sizeof(mPlatformRecoveryOptionVariableList)/sizeof(mPlatformRecoveryOptionVariableList[0]); ListIndex++) {
    for (Index = 0; ; Index++) {
      UnicodeSPrint (PlatformRecoveryOptionName, sizeof(PlatformRecoveryOptionName), L"%s%04x", mPlatformRecoveryOptionVariableList[ListIndex], Index);
      Status = GetVariable2 (PlatformRecoveryOptionName, &gEfiGlobalVariableGuid, &Variable, &Size);
      if (!EFI_ERROR(Status)) {
        DumpLoadOption (PlatformRecoveryOptionName, Variable, Size);
      } else {
        break;
      }
    }
  }
}

VOID
DumpOsRecoveryOptionVariable (
  VOID
  )
{
}

VOID
DumpKeyOptionVariable (
  VOID
  )
{
  VOID        *Variable;
  UINTN       ListIndex;
  UINTN       Size;
  UINTN       Index;
  EFI_STATUS  Status;
  CHAR16      KeyOptionName[sizeof(L"Key####")];

  for (ListIndex = 0; ListIndex < sizeof(mKeyOptionVariableList)/sizeof(mKeyOptionVariableList[0]); ListIndex++) {
    for (Index = 0; ; Index++) {
      UnicodeSPrint (KeyOptionName, sizeof(KeyOptionName), L"%s%04x", mKeyOptionVariableList[ListIndex], Index);
      Status = GetVariable2 (KeyOptionName, &gEfiGlobalVariableGuid, &Variable, &Size);
      if (!EFI_ERROR(Status)) {
        DumpKeyOption (KeyOptionName, Variable, Size);
      } else {
        break;
      }
    }
  }
}

EFI_STATUS
TestPointDumpBootVariable (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "==== TestPointDumpBootVariable - Enter\n"));

  DumpLoadOptionVariable ();
  DumpPlatformRecoveryOptionVariable ();
  DumpOsRecoveryOptionVariable ();
  DumpKeyOptionVariable ();

  DEBUG ((DEBUG_INFO, "==== TestPointDumpBootVariable - Exit\n"));

  // Check - TBD
  return EFI_SUCCESS;
}