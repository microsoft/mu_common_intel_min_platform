/** @file
  This file include all platform action which can be customized by IBV/OEM.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "BdsPlatform.h"
#include <Guid/EventGroup.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/PciRootBridgeIo.h>

#include <Protocol/BlockIo.h>
#include <Library/IoLib.h>
#include <Library/PciLib.h>
#include <Guid/EventGroup.h>

#include <Library/Tcg2PhysicalPresenceLib.h>

#ifdef _MSC_VER
#pragma optimize("g", off)
#endif

#include <Library/HobLib.h>
#include <Protocol/UsbIo.h>


extern EFI_STATUS EfiBootManagerDispatchDeferredImages(VOID);

GLOBAL_REMOVE_IF_UNREFERENCED EFI_BOOT_MODE                 gBootMode;

BOOLEAN                      gPPRequireUIConfirm;

//
// Internal shell mode
//
GLOBAL_REMOVE_IF_UNREFERENCED UINT32         mShellModeColumn;
GLOBAL_REMOVE_IF_UNREFERENCED UINT32         mShellModeRow;
GLOBAL_REMOVE_IF_UNREFERENCED UINT32         mShellHorizontalResolution;
GLOBAL_REMOVE_IF_UNREFERENCED UINT32         mShellVerticalResolution;
//
// BDS Platform Functions
//


/**
  The handle on the path we get might be not the display device.
  We must check it.

  @todo fix the parameters

  @retval  TRUE         PCI class type is VGA.
  @retval  FALSE        PCI class type isn't VGA.
**/
BOOLEAN
IsVgaHandle (
  IN EFI_HANDLE Handle
  )
{
  EFI_PCI_IO_PROTOCOL *PciIo;
  PCI_TYPE00          Pci;
  EFI_STATUS          Status;

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo
                  );

  if (!EFI_ERROR (Status)) {
    Status = PciIo->Pci.Read (
                          PciIo,
                          EfiPciIoWidthUint32,
                          0,
                          sizeof (Pci) / sizeof (UINT32),
                          &Pci
                          );

    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "  PCI CLASS CODE    = 0x%x\n", Pci.Hdr.ClassCode [2]));
      DEBUG ((DEBUG_INFO, "  PCI SUBCLASS CODE = 0x%x\n", Pci.Hdr.ClassCode [1]));

      if (IS_PCI_VGA (&Pci) || IS_PCI_OLD_VGA (&Pci)) {
        DEBUG ((DEBUG_INFO, "  \nPCI VGA Device Found\n"));
        return TRUE;
      }
    }
  }
  return FALSE;
}

/**
  An empty function to pass error checking of CreateEventEx ().

  This empty function ensures that EVT_NOTIFY_SIGNAL_ALL is error
  checked correctly since it is now mapped into CreateEventEx() in UEFI 2.0.

  @param  Event                 Event whose notification function is being invoked.
  @param  Context               The pointer to the notification function's context,
                                which is implementation-dependent.
**/
VOID
EFIAPI
InternalBdsEmptyCallbackFuntion (
  IN EFI_EVENT                Event,
  IN VOID                     *Context
  )
{
  return;
}

VOID
ExitPmAuth (
  VOID
  )
{
  EFI_HANDLE                 Handle;
  EFI_STATUS                 Status;
  EFI_EVENT                  EndOfDxeEvent;

  DEBUG((DEBUG_INFO,"ExitPmAuth ()- Start\n"));
  //
  // Prepare S3 information, this MUST be done before ExitPmAuth/EndOfDxe
  //
  //
  // Since PI1.2.1, we need signal EndOfDxe as ExitPmAuth
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  InternalBdsEmptyCallbackFuntion,
                  NULL,
                  &gEfiEndOfDxeEventGroupGuid,
                  &EndOfDxeEvent
                  );
  ASSERT_EFI_ERROR (Status);
  gBS->SignalEvent (EndOfDxeEvent);
  gBS->CloseEvent (EndOfDxeEvent);
  DEBUG((DEBUG_INFO,"All EndOfDxe callbacks have returned successfully\n"));

  //
  // NOTE: We need install DxeSmmReadyToLock directly here because many boot script is added via ExitPmAuth/EndOfDxe callback.
  // If we install them at same callback, these boot script will be rejected because BootScript Driver runs first to lock them done.
  // So we seperate them to be 2 different events, ExitPmAuth is last chance to let platform add boot script. DxeSmmReadyToLock will
  // make boot script save driver lock down the interface.
  //
  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);
  DEBUG((DEBUG_INFO,"ExitPmAuth ()- End\n"));
}

VOID
ConnectRootBridge (
  BOOLEAN Recursive
  )
{
  UINTN                            RootBridgeHandleCount;
  EFI_HANDLE                       *RootBridgeHandleBuffer;
  UINTN                            RootBridgeIndex;

  RootBridgeHandleCount = 0;
  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiPciRootBridgeIoProtocolGuid,
         NULL,
         &RootBridgeHandleCount,
         &RootBridgeHandleBuffer
         );
  for (RootBridgeIndex = 0; RootBridgeIndex < RootBridgeHandleCount; RootBridgeIndex++) {
    gBS->ConnectController (RootBridgeHandleBuffer[RootBridgeIndex], NULL, NULL, Recursive);
  }
}


BOOLEAN
IsGopDevicePath (
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  )
{
  while (!IsDevicePathEndType (DevicePath)) {
    if (DevicePathType (DevicePath) == ACPI_DEVICE_PATH &&
        DevicePathSubType (DevicePath) == ACPI_ADR_DP) {
      return TRUE;
    }
    DevicePath = NextDevicePathNode (DevicePath);
  }
  return FALSE;
}

/**
  Connect the USB short form device path.

  @param DevicePath   USB short form device path

  @retval EFI_SUCCESS           Successfully connected the USB device
  @retval EFI_NOT_FOUND         Cannot connect the USB device
  @retval EFI_INVALID_PARAMETER The device path is invalid.
**/
EFI_STATUS
ConnectUsbShortFormDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath
  )
{
  EFI_STATUS                            Status;
  EFI_HANDLE                            *Handles;
  UINTN                                 HandleCount;
  UINTN                                 Index;
  EFI_PCI_IO_PROTOCOL                   *PciIo;
  UINT8                                 Class[3];
  BOOLEAN                               AtLeastOneConnected;

  //
  // Check the passed in parameters
  //
  if (DevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((DevicePathType (DevicePath) != MESSAGING_DEVICE_PATH) ||
      ((DevicePathSubType (DevicePath) != MSG_USB_CLASS_DP) && (DevicePathSubType (DevicePath) != MSG_USB_WWID_DP))
     ) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Find the usb host controller firstly, then connect with the remaining device path
  //
  AtLeastOneConnected = FALSE;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiPciIoProtocolGuid,
                    (VOID **) &PciIo
                    );
    if (!EFI_ERROR (Status)) {
      //
      // Check whether the Pci device is the wanted usb host controller
      //
      Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x09, 3, &Class);
      if (!EFI_ERROR (Status) &&
          ((PCI_CLASS_SERIAL == Class[2]) && (PCI_CLASS_SERIAL_USB == Class[1]))
         ) {
        Status = gBS->ConnectController (
                        Handles[Index],
                        NULL,
                        DevicePath,
                        FALSE
                        );
        if (!EFI_ERROR(Status)) {
          AtLeastOneConnected = TRUE;
        }
      }
    }
  }

  return AtLeastOneConnected ? EFI_SUCCESS : EFI_NOT_FOUND;
}


/**
  Update the ConIn variable with USB Keyboard device path,if its not already exists in ConIn
**/
VOID
EnumUsbKeyboard (
  VOID
  )
{
  UINTN                     DevicePathSize;
  EFI_DEVICE_PATH_PROTOCOL  *VarConIn;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePathInstance;
  EFI_DEVICE_PATH_PROTOCOL  *Next;
  BOOLEAN                   UsbKeyboard;

  UsbKeyboard = FALSE;
  GetEfiGlobalVariable2 (L"ConIn", (VOID **) &VarConIn, NULL);

  //
  // If ConIn variable is empty, need to enumerate USB keyboard device path
  //
  do {
    DevicePathInstance = GetNextDevicePathInstance (
                           &VarConIn,
                           &DevicePathSize
                           );

    if (DevicePathInstance == NULL) {
      //
      // The instance is NULL, it means the VarConIn is null, escape the DO loop,
      // and need to add USB keyboard dev path.
      //
      break;
    }

    Next = DevicePathInstance;
    while (!IsDevicePathEndType(Next)) {
      //
      // Checking the device path to see the USB keyboard existance.
      //
      if ((Next->Type    == MESSAGING_DEVICE_PATH) &&
          (Next->SubType == MSG_USB_CLASS_DP) &&
          (((USB_CLASS_DEVICE_PATH *) Next)->DeviceClass == CLASS_HID) &&
          (((USB_CLASS_DEVICE_PATH *) Next)->DeviceSubClass == SUBCLASS_BOOT) &&
          (((USB_CLASS_DEVICE_PATH *) Next)->DeviceProtocol == PROTOCOL_KEYBOARD)) {
        DEBUG ((DEBUG_INFO, "[EnumUsbKeyboard] USB keyboard path exists\n"));
        UsbKeyboard = TRUE;

        break;
      }
      Next = NextDevicePathNode (Next);
    } // while (!IsDevicePathEndType(Next));

    if (DevicePathInstance != NULL) {
      FreePool (DevicePathInstance);
    }
  } while (VarConIn != NULL);

  //
  //  USB keyboard device path does not exist, So add it to the ConIn
  //
  if (!UsbKeyboard) {
    DEBUG ((DEBUG_INFO, "[EnumUsbKeyboard] Adding USB keyboard device path to ConIn.\n"));
    EfiBootManagerUpdateConsoleVariable (ConIn, (EFI_DEVICE_PATH_PROTOCOL *) &gUsbClassKeyboardDevicePath, NULL);
  }

  if (VarConIn != NULL) {
    FreePool (VarConIn);
  }
}

/**
  Return whether the device is trusted console.

  @param Device  The device to be tested.

  @retval TRUE   The device can be trusted.
  @retval FALSE  The device cannot be trusted.
**/
BOOLEAN
IsTrustedConsole (
  EFI_DEVICE_PATH_PROTOCOL  *Device
  )
{

  if(Device == NULL) {
    return FALSE;
  }

  if (CompareMem (Device, &gPlatformIGDDevice, GetDevicePathSize ((EFI_DEVICE_PATH_PROTOCOL *) &gPlatformIGDDevice) - END_DEVICE_PATH_LENGTH) == 0) {
    return TRUE;
  }

  if (CompareMem (Device, &gUsbClassKeyboardDevicePath, GetDevicePathSize ((EFI_DEVICE_PATH_PROTOCOL *) &gUsbClassKeyboardDevicePath) - END_DEVICE_PATH_LENGTH) == 0) {
    return TRUE;
  }
  return FALSE;
}

/**
  The function connects the trusted consoles.
**/
VOID
ConnectTrustedConsole (
  VOID
  )
{
  EFI_DEVICE_PATH_PROTOCOL     *Consoles;
  EFI_DEVICE_PATH_PROTOCOL     *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL     *Instance;
  EFI_DEVICE_PATH_PROTOCOL     *Next;
  UINTN                        Size;
  UINTN                        Index;
  EFI_HANDLE                   Handle;
  EFI_STATUS                   Status;
  CHAR16                       *ConsoleVar[] = {L"ConIn", L"ConOut"};

  for (Index = 0; Index < sizeof (ConsoleVar) / sizeof (ConsoleVar[0]); Index++) {
    GetEfiGlobalVariable2 (ConsoleVar[Index], &Consoles, NULL);

    TempDevicePath = Consoles;
    do {
      Instance = GetNextDevicePathInstance (&TempDevicePath, &Size);
      if (Instance == NULL) {
        break;
      }
      if (IsTrustedConsole (Instance)) {
        if ((DevicePathType (Instance) == MESSAGING_DEVICE_PATH) &&
            ((DevicePathSubType (Instance) == MSG_USB_CLASS_DP) || (DevicePathSubType (Instance) == MSG_USB_WWID_DP))
           ) {
          ConnectUsbShortFormDevicePath (Instance);
        } else {
          for (Next = Instance; !IsDevicePathEnd (Next); Next = NextDevicePathNode (Next)) {
            if (DevicePathType (Next) == ACPI_DEVICE_PATH && DevicePathSubType (Next) == ACPI_ADR_DP) {
              break;
            } else if (DevicePathType (Next) == HARDWARE_DEVICE_PATH &&
                       DevicePathSubType (Next) == HW_CONTROLLER_DP &&
                       DevicePathType (NextDevicePathNode (Next)) == ACPI_DEVICE_PATH &&
                       DevicePathSubType (NextDevicePathNode (Next)) == ACPI_ADR_DP
                       ) {
              break;
            }
          }
          if (!IsDevicePathEnd (Next)) {
            SetDevicePathEndNode (Next);
            Status = EfiBootManagerConnectDevicePath (Instance, &Handle);
            if (!EFI_ERROR (Status)) {
              gBS->ConnectController (Handle, NULL, NULL, TRUE);
            }
          } else {
            EfiBootManagerConnectDevicePath (Instance, NULL);
          }
        }
      }
      FreePool (Instance);
    } while (TempDevicePath != NULL);

    if (Consoles != NULL) {
      FreePool (Consoles);
    }
  }
}

/**
  The function connects the trusted consoles and then call the PP processing library interface.
**/
VOID
ProcessTcgPp (
  VOID
  )
{
  gPPRequireUIConfirm |= Tcg2PhysicalPresenceLibNeedUserConfirm();

  if (gPPRequireUIConfirm) {
    ConnectTrustedConsole ();
  }

  Tcg2PhysicalPresenceLibProcessRequest (NULL);
}

/**
  Remove all GOP device path instance from DevicePath and add the Gop to the DevicePath.
**/
EFI_DEVICE_PATH_PROTOCOL *
UpdateDevicePath (
  EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  EFI_DEVICE_PATH_PROTOCOL *Gop
  )
{
  UINTN                    Size;
  UINTN                    GopSize;
  EFI_DEVICE_PATH_PROTOCOL *Temp;
  EFI_DEVICE_PATH_PROTOCOL *Return;
  EFI_DEVICE_PATH_PROTOCOL *Instance;
  BOOLEAN                  Exist;

  Exist = FALSE;
  Return = NULL;
  GopSize = GetDevicePathSize (Gop);
  do {
    Instance = GetNextDevicePathInstance (&DevicePath, &Size);
    if (Instance == NULL) {
      break;
    }
    if (!IsGopDevicePath (Instance) ||
        (Size == GopSize && CompareMem (Instance, Gop, GopSize) == 0)
       ) {
      if (Size == GopSize && CompareMem (Instance, Gop, GopSize) == 0) {
        Exist = TRUE;
      }
      Temp = Return;
      Return = AppendDevicePathInstance (Return, Instance);
      if (Temp != NULL) {
        FreePool (Temp);
      }
    }
    FreePool (Instance);
  } while (DevicePath != NULL);

  if (!Exist) {
    Temp = Return;
    Return = AppendDevicePathInstance (Return, Gop);
    if (Temp != NULL) {
      FreePool (Temp);
    }
  }
  return Return;
}

#ifdef _MSC_VER
#pragma optimize("g", off)
#endif

/**
  Check if current BootCurrent variable is internal shell boot option.

  @retval  TRUE         BootCurrent is internal shell.
  @retval  FALSE        BootCurrent is not internal shell.
**/
BOOLEAN
BootCurrentIsInternalShell (
  VOID
  )
{
  UINTN                         VarSize;
  UINT16                        BootCurrent;
  CHAR16                        BootOptionName[16];
  UINT8                         *BootOption;
  UINT8                         *Ptr;
  EFI_DEVICE_PATH_PROTOCOL      *BootDevicePath;
  BOOLEAN                       Result;
  EFI_STATUS                    Status;
  EFI_DEVICE_PATH_PROTOCOL      *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL      *LastDeviceNode;
  EFI_GUID                      *GuidPoint;

  BootOption     = NULL;
  BootDevicePath = NULL;
  Result         = FALSE;

  //
  // Get BootCurrent variable
  //
  VarSize = sizeof (UINT16);
  Status = gRT->GetVariable (
                  L"BootCurrent",
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &VarSize,
                  &BootCurrent
                  );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Create boot option Bootxxxx from BootCurrent
  //
  UnicodeSPrint (BootOptionName, sizeof(BootOptionName), L"Boot%04X", BootCurrent);

  GetEfiGlobalVariable2 (BootOptionName, (VOID **) &BootOption, &VarSize);
  if (BootOption == NULL || VarSize == 0) {
    return FALSE;
  }

  Ptr = BootOption;
  Ptr += sizeof (UINT32);
  Ptr += sizeof (UINT16);
  Ptr += StrSize ((CHAR16 *) Ptr);
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *) Ptr;
  LastDeviceNode = TempDevicePath;
  while (!IsDevicePathEnd (TempDevicePath)) {
    LastDeviceNode = TempDevicePath;
    TempDevicePath = NextDevicePathNode (TempDevicePath);
  }
  GuidPoint = EfiGetNameGuidFromFwVolDevicePathNode (
                (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *) LastDeviceNode
                );
  if ((GuidPoint != NULL) &&
      ((CompareGuid (GuidPoint, &gUefiShellFileGuid)))
    ) {
    //
    // if this option is internal shell, return TRUE
    //
    Result = TRUE;
  }

  if (BootOption != NULL) {
    FreePool (BootOption);
    BootOption = NULL;
  }

  return Result;
}

/**
  This function will change video resolution and text mode
  for internl shell when internal shell is launched.

  @param   None.

  @retval  EFI_SUCCESS  Mode is changed successfully.
  @retval  Others       Mode failed to changed.
**/
EFI_STATUS
EFIAPI
ChangeModeForInternalShell (
  VOID
  )
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL          *GraphicsOutput;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL       *SimpleTextOut;
  UINTN                                 SizeOfInfo;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *Info;
  UINT32                                MaxGopMode;
  UINT32                                MaxTextMode;
  UINT32                                ModeNumber;
  UINTN                                 HandleCount;
  EFI_HANDLE                            *HandleBuffer;
  EFI_STATUS                            Status;
  UINTN                                 Index;
  UINTN                                 CurrentColumn;
  UINTN                                 CurrentRow;

  Status = gBS->HandleProtocol (
                  gST->ConsoleOutHandle,
                  &gEfiGraphicsOutputProtocolGuid,
                  (VOID**)&GraphicsOutput
                  );
  if (EFI_ERROR (Status)) {
    GraphicsOutput = NULL;
  }

  Status = gBS->HandleProtocol (
                  gST->ConsoleOutHandle,
                  &gEfiSimpleTextOutProtocolGuid,
                  (VOID**)&SimpleTextOut
                  );
  if (EFI_ERROR (Status)) {
    SimpleTextOut = NULL;
  }

  if ((GraphicsOutput == NULL) || (SimpleTextOut == NULL)) {
    return EFI_UNSUPPORTED;
  }

  MaxGopMode  = GraphicsOutput->Mode->MaxMode;
  MaxTextMode = SimpleTextOut->Mode->MaxMode;

  //
  // 1. If current video resolution is same with new video resolution,
  //    video resolution need not be changed.
  //    1.1. If current text mode is same with new text mode, text mode need not be change.
  //    1.2. If current text mode is different with new text mode, text mode need be change to new text mode.
  // 2. If current video resolution is different with new video resolution, we need restart whole console drivers.
  //
  for (ModeNumber = 0; ModeNumber < MaxGopMode; ModeNumber++) {
    Status = GraphicsOutput->QueryMode (
                       GraphicsOutput,
                       ModeNumber,
                       &SizeOfInfo,
                       &Info
                       );
    if (!EFI_ERROR (Status)) {
      if ((Info->HorizontalResolution == mShellHorizontalResolution) &&
          (Info->VerticalResolution == mShellVerticalResolution)) {
        if ((GraphicsOutput->Mode->Info->HorizontalResolution == mShellHorizontalResolution) &&
            (GraphicsOutput->Mode->Info->VerticalResolution == mShellVerticalResolution)) {
          //
          // If current video resolution is same with new resolution,
          // then check if current text mode is same with new text mode.
          //
          Status = SimpleTextOut->QueryMode (SimpleTextOut, SimpleTextOut->Mode->Mode, &CurrentColumn, &CurrentRow);
          ASSERT_EFI_ERROR (Status);
          if (CurrentColumn == mShellModeColumn && CurrentRow == mShellModeRow) {
            //
            // Current text mode is same with new text mode, text mode need not be change.
            //
            FreePool (Info);
            return EFI_SUCCESS;
          } else {
            //
            // Current text mode is different with new text mode, text mode need be change to new text mode.
            //
            for (Index = 0; Index < MaxTextMode; Index++) {
              Status = SimpleTextOut->QueryMode (SimpleTextOut, Index, &CurrentColumn, &CurrentRow);
              if (!EFI_ERROR(Status)) {
                if ((CurrentColumn == mShellModeColumn) && (CurrentRow == mShellModeRow)) {
                  //
                  // New text mode is supported, set it.
                  //
                  Status = SimpleTextOut->SetMode (SimpleTextOut, Index);
                  ASSERT_EFI_ERROR (Status);
                  //
                  // Update text mode PCD.
                  //
                  PcdSet32S (PcdConOutColumn, mShellModeColumn);
                  PcdSet32S (PcdConOutRow, mShellModeRow);
                  FreePool (Info);
                  return EFI_SUCCESS;
                }
              }
            }
            if (Index == MaxTextMode) {
              //
              // If new text mode is not supported, return error.
              //
              FreePool (Info);
              return EFI_UNSUPPORTED;
            }
          }
        } else {
          FreePool (Info);
          //
          // If current video resolution is not same with the new one, set new video resolution.
          // In this case, the driver which produces simple text out need be restarted.
          //
          Status = GraphicsOutput->SetMode (GraphicsOutput, ModeNumber);
          if (!EFI_ERROR (Status)) {
            //
            // Set PCD to restart GraphicsConsole and Consplitter to change video resolution
            // and produce new text mode based on new resolution.
            //
            PcdSet32S (PcdVideoHorizontalResolution, mShellHorizontalResolution);
            PcdSet32S (PcdVideoVerticalResolution, mShellVerticalResolution);
            PcdSet32S (PcdConOutColumn, mShellModeColumn);
            PcdSet32S (PcdConOutRow, mShellModeRow);

            Status = gBS->LocateHandleBuffer (
                             ByProtocol,
                             &gEfiSimpleTextOutProtocolGuid,
                             NULL,
                             &HandleCount,
                             &HandleBuffer
                             );
            if (!EFI_ERROR (Status)) {
              for (Index = 0; Index < HandleCount; Index++) {
                gBS->DisconnectController (HandleBuffer[Index], NULL, NULL);
              }
              for (Index = 0; Index < HandleCount; Index++) {
                gBS->ConnectController (HandleBuffer[Index], NULL, NULL, TRUE);
              }
              if (HandleBuffer != NULL) {
                FreePool (HandleBuffer);
              }
              break;
            }
          }
        }
      }
      FreePool (Info);
    }
  }

  if (ModeNumber == MaxGopMode) {
    //
    // If the new resolution is not supported, return error.
    //
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  ReadyToBoot callback to set video and text mode for internal shell boot.
  That will not connect USB controller while CSM and FastBoot are disabled, we need to connect them
  before booting to Shell for showing USB devices in Shell.

  When FastBoot is enabled and Windows Console is the chosen Console behavior, input devices will not be connected
  by default. Hence, when booting to EFI shell, connecting input consoles are required.

  @param  Event   Pointer to this event
  @param  Context Event hanlder private data

  @retval None.
**/
VOID
EFIAPI
OnReadyToBootCallBack (
  IN  EFI_EVENT                 Event,
  IN  VOID                      *Context
  )
{
  DEBUG ((EFI_D_INFO, "OnReadyToBootCallBack\n"));

  if (BootCurrentIsInternalShell ()) {

    ChangeModeForInternalShell ();
      EfiBootManagerConnectAllDefaultConsoles();
      gDS->Dispatch ();
  }
}

/**
  Platform Bds init. Incude the platform firmware vendor, revision
  and so crc check.
**/
VOID
EFIAPI
PlatformBootManagerBeforeConsole (
  VOID
  )
{
  EFI_STATUS                          Status;
  UINTN                               Index;
  EFI_DEVICE_PATH_PROTOCOL            *VarConOut;
  EFI_DEVICE_PATH_PROTOCOL            *VarConIn;
  EFI_DEVICE_PATH_PROTOCOL            *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL            *ConsoleOut;
  EFI_DEVICE_PATH_PROTOCOL            *Temp;
  EFI_DEVICE_PATH_PROTOCOL            *Instance;
  EFI_DEVICE_PATH_PROTOCOL            *Next;
  EFI_HANDLE                          VideoHandle;
  BOOLEAN                             IsIgd;
  EFI_EVENT                           Event;
  UINTN                               InstanceSize;

  DEBUG ((EFI_D_INFO, "PlatformBootManagerBeforeConsole\n"));

  Status = EFI_SUCCESS;
  //
  // Append Usb Keyboard short form DevicePath into "ConInDev"
  //
  EfiBootManagerUpdateConsoleVariable (
    ConInDev,
    (EFI_DEVICE_PATH_PROTOCOL *) &gUsbClassKeyboardDevicePath,
    NULL
    );

  //
  // Get user defined text mode for internal shell only once.
  //
  mShellHorizontalResolution = PcdGet32 (PcdSetupVideoHorizontalResolution);
  mShellVerticalResolution   = PcdGet32 (PcdSetupVideoVerticalResolution);
  mShellModeColumn           = PcdGet32 (PcdSetupConOutColumn);
  mShellModeRow              = PcdGet32 (PcdSetupConOutRow);

  //
  // Create event to set proper video resolution and text mode for internal shell.
  //
  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             OnReadyToBootCallBack,
             NULL,
             &Event
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Connect Root Bridge to make PCI BAR resource allocated and all PciIo created
  //
  ConnectRootBridge (FALSE);

  //
  // Update ConOut variable according to the PrimaryDisplay setting
  //
  GetEfiGlobalVariable2 (L"ConOut", &ConsoleOut, NULL);
  //
  // Add IGD to ConOut
  //
  IsIgd  = TRUE;
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *) &gPlatformIGDDevice;
  Status = gBS->LocateDevicePath (&gEfiPciIoProtocolGuid, &TempDevicePath, &VideoHandle);

  if ((VideoHandle != NULL) && (IsIgd == TRUE)) {
    //
    // Connect the GOP driver
    //
    gBS->ConnectController (VideoHandle, NULL, NULL, TRUE);

    //
    // Get the GOP device path
    // NOTE: We may get a device path that contains Controller node in it.
    //
    TempDevicePath = EfiBootManagerGetGopDevicePath (VideoHandle);
    if (TempDevicePath != NULL) {
      Temp = ConsoleOut;
      ConsoleOut = UpdateDevicePath (ConsoleOut, TempDevicePath);
      if (Temp != NULL) {
        FreePool (Temp);
      }
      FreePool (TempDevicePath);
      Status = gRT->SetVariable (
                      L"ConOut",
                      &gEfiGlobalVariableGuid,
                      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                      GetDevicePathSize (ConsoleOut),
                      ConsoleOut
                      );
    }
  }
  //
  // Fill ConIn/ConOut in Full Configuration boot mode
  //
  DEBUG ((DEBUG_INFO, "PlatformBootManagerInit - %x\n", gBootMode));

  if (gBootMode == BOOT_WITH_FULL_CONFIGURATION ||
      gBootMode == BOOT_WITH_DEFAULT_SETTINGS ||
      gBootMode == BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS ||
      gBootMode == BOOT_IN_RECOVERY_MODE) {

    GetEfiGlobalVariable2 (L"ConOut", &VarConOut, NULL);   if (VarConOut != NULL) { FreePool (VarConOut); }
    GetEfiGlobalVariable2 (L"ConIn", &VarConIn, NULL);    if (VarConIn  != NULL) { FreePool (VarConIn);  }

    if (VarConOut == NULL || VarConIn == NULL) {
      //
      // Only fill ConIn/ConOut when ConIn/ConOut is empty because we may drop to Full Configuration boot mode in non-first boot
      //
      //
      // Update ConOutDevicePath (just in case it is wrong at build phase)
      // To be enabled later.
      //
//      PlatformPatchConOutDevicePath ();

      for (Index = 0; gPlatformConsole[Index].DevicePath != NULL; Index++) {
        //
        // Update the console variable with the connect type
        //
        if ((gPlatformConsole[Index].ConnectType & CONSOLE_IN) == CONSOLE_IN) {
          EfiBootManagerUpdateConsoleVariable (ConIn, gPlatformConsole[Index].DevicePath, NULL);
        }
        if ((gPlatformConsole[Index].ConnectType & CONSOLE_OUT) == CONSOLE_OUT) {
          EfiBootManagerUpdateConsoleVariable (ConOut, gPlatformConsole[Index].DevicePath, NULL);
        }
        if ((gPlatformConsole[Index].ConnectType & STD_ERROR) == STD_ERROR) {
          EfiBootManagerUpdateConsoleVariable (ErrOut, gPlatformConsole[Index].DevicePath, NULL);
        }
      }
    }
    else {
      if (gBootMode == BOOT_WITH_DEFAULT_SETTINGS) {

        GetEfiGlobalVariable2 (L"ConIn", &VarConIn, NULL);
        Instance      = GetNextDevicePathInstance (&VarConIn, &InstanceSize);
        InstanceSize -= END_DEVICE_PATH_LENGTH;

        while (Instance != NULL) {
          Next = Instance;
          while (!IsDevicePathEndType (Next)) {
            Next = NextDevicePathNode (Next);
            if (DevicePathType (Next) == MESSAGING_DEVICE_PATH && DevicePathSubType (Next) == MSG_VENDOR_DP) {
              //
              // Restoring default serial device path
              //
              EfiBootManagerUpdateConsoleVariable (ConIn, NULL, Instance);
              EfiBootManagerUpdateConsoleVariable (ConOut, NULL, Instance);
            }
          }
          FreePool(Instance);
          Instance      = GetNextDevicePathInstance (&VarConIn, &InstanceSize);
          InstanceSize -= END_DEVICE_PATH_LENGTH;
        }
      }
    }
  }

  EnumUsbKeyboard ();

  //
  // Dynamically register hot key: F2/F7/Enter
  //
  RegisterDefaultBootOption ();
  RegisterStaticHotkey ();

  //
  // Connect Root Bridge to make PCI BAR resource allocated.
  // Then exit PM auth before Legacy OPROM run.
  //
  PERF_START_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7010);
  ConnectRootBridge (FALSE);
  if (PcdGetBool (PcdTpm2Enable)) {
    ProcessTcgPp ();
  }
  PERF_END_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7011);

  //
  // We should make all UEFI memory and GCD information populated before ExitPmAuth.
  // SMM may consume these information.
  //
  MemoryTest((EXTENDMEM_COVERAGE_LEVEL) PcdGet32 (PcdPlatformMemoryCheck));

  PERF_START_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7020);
  ExitPmAuth ();
  PERF_END_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7021);

  //
  // Dispatch the deferred 3rd party images.
  //
  EfiBootManagerDispatchDeferredImages ();

}


/**
  Connect with predeined platform connect sequence,
  the OEM/IBV can customize with their own connect sequence.

  @param[in] BootMode          Boot mode of this boot.
**/
VOID
ConnectSequence (
  IN EFI_BOOT_MODE         BootMode
  )
{
  EfiBootManagerConnectAll ();
}

/**
  The function is to consider the boot order which is not in our expectation.
  In the case that we need to re-sort the boot option.

  @retval  TRUE         Need to sort Boot Option.
  @retval  FALSE        Don't need to sort Boot Option.
**/
BOOLEAN
IsNeedSortBootOption (
  VOID
  )
{
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  UINTN                         BootOptionCount;

  BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);

  //
  // If setup is the first priority in boot option, we need to sort boot option.
  //
  if ((BootOptionCount > 1) &&
      (((StrnCmp (BootOptions->Description, L"Enter Setup", StrLen (L"Enter Setup"))) == 0) ||
       ((StrnCmp (BootOptions->Description, L"BootManagerMenuApp", StrLen (L"BootManagerMenuApp"))) == 0))) {
    return TRUE;
  }

  return FALSE;
}

/**
  The function will excute with as the platform policy, current policy
  is driven by boot mode. IBV/OEM can customize this code for their specific
  policy action.

  @param DriverOptionList - The header of the driver option link list
  @param BootOptionList   - The header of the boot option link list
  @param ProcessCapsules  - A pointer to ProcessCapsules()
  @param BaseMemoryTest   - A pointer to BaseMemoryTest()
**/
VOID
EFIAPI
PlatformBootManagerAfterConsole (
  VOID
  )
{
  EFI_BOOT_MODE                 LocalBootMode;

  DEBUG ((EFI_D_INFO, "PlatformBootManagerAfterConsole\n"));

  //
  // Get current Boot Mode
  //
  LocalBootMode = gBootMode;
  DEBUG ((DEBUG_INFO, "Current local bootmode - %x\n", LocalBootMode));

  //
  // Go the different platform policy with different boot mode
  // Notes: this part code can be change with the table policy
  //
  switch (LocalBootMode) {

  case BOOT_ASSUMING_NO_CONFIGURATION_CHANGES:
  case BOOT_WITH_MINIMAL_CONFIGURATION:
  case BOOT_ON_S4_RESUME:
    //
    // Perform some platform specific connect sequence
    //
    PERF_START_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7050);
    ConnectSequence (LocalBootMode);
    PERF_END_EX(NULL,"EventRec", NULL, AsmReadTsc(), 0x7051);

    break;

  case BOOT_WITH_FULL_CONFIGURATION:
  case BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS:
  case BOOT_WITH_DEFAULT_SETTINGS:
  default:
    //
    // Perform some platform specific connect sequence
    //
    ConnectSequence (LocalBootMode);

    //
    // Only in Full Configuration boot mode we do the enumeration of boot device
    //
    //
    // Dispatch all but Storage Oprom explicitly, because we assume Int13Thunk driver is there.
    //
    EfiBootManagerRefreshAllBootOption ();

    if (IsNeedSortBootOption()) {
      EfiBootManagerSortLoadOptionVariable (LoadOptionTypeBoot, CompareBootOption);
    }
    //
    // PXE boot option may appear after boot option enumeration
    //

    break;
  }

  Print (L"Press F7 for BootMenu!\n");

    EfiBootManagerRefreshAllBootOption ();
      EfiBootManagerSortLoadOptionVariable (LoadOptionTypeBoot, CompareBootOption);




}

