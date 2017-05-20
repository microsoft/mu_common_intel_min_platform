/** @file
  Defined the platform specific device path which will be used by
  platform Bbd to perform the platform policy connect.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "BdsPlatform.h"

//
// Predefined platform root bridge
//
GLOBAL_REMOVE_IF_UNREFERENCED PLATFORM_ROOT_BRIDGE_DEVICE_PATH  gPlatformRootBridge0 = {
  gPciRootBridge,
  gEndEntire
};

GLOBAL_REMOVE_IF_UNREFERENCED USB_CLASS_FORMAT_DEVICE_PATH gUsbClassKeyboardDevicePath = {
  {
    {
      MESSAGING_DEVICE_PATH,
      MSG_USB_CLASS_DP,
      {
        (UINT8) (sizeof (USB_CLASS_DEVICE_PATH)),
        (UINT8) ((sizeof (USB_CLASS_DEVICE_PATH)) >> 8)
      }
    },
    0xffff,           // VendorId
    0xffff,           // ProductId
    CLASS_HID,        // DeviceClass
    SUBCLASS_BOOT,    // DeviceSubClass
    PROTOCOL_KEYBOARD // DeviceProtocol
  },
  gEndEntire
};

//
// Onboard VGA controller device path
//
GLOBAL_REMOVE_IF_UNREFERENCED PLATFORM_ONBOARD_CONTROLLER_DEVICE_PATH         gPlatformIGDDevice = {
  gPciRootBridge,
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_PCI_DP,
      {
        (UINT8) (sizeof (PCI_DEVICE_PATH)),
        (UINT8) ((sizeof (PCI_DEVICE_PATH)) >> 8)
      }
    },
    0x0,
    0x2
  },
  gEndEntire
};

//
// Predefined platform default console device path
//
GLOBAL_REMOVE_IF_UNREFERENCED BDS_CONSOLE_CONNECT_ENTRY         gPlatformConsole[] = {
  {
    (EFI_DEVICE_PATH_PROTOCOL *) &gUsbClassKeyboardDevicePath,
    CONSOLE_IN
  },
  {
    NULL,
    0
  }
};

GLOBAL_REMOVE_IF_UNREFERENCED USB_CLASS_FORMAT_DEVICE_PATH gUsbClassMassStorageDevice = {
  {
    {
      MESSAGING_DEVICE_PATH,
      MSG_USB_CLASS_DP,
      {
        (UINT8) (sizeof (USB_CLASS_DEVICE_PATH)),
        (UINT8) ((sizeof (USB_CLASS_DEVICE_PATH)) >> 8)
      }
    },
    0xffff,  // VendorId
    0xffff,  // ProductId
    0x08,    // DeviceClass    - USB Mass Storage Class
    0x06,    // DeviceSubClass - SCSI Transparent Command Set
    0xff     // DeviceProtocol - Match any Device Protocol
  },
  gEndEntire
};
