/** @file
TestPointPciSpeedInfoLib.h

An interface for platforms to define PCI devices which is checked
at boot. Simply create an array of DEVICE_PCI_INFO structures for every
device desired, and an error will be logged if it is not found on the bus. In
cases where the device won't boot to the OS, this can help quickly identify
if the cause is due to a PCI device not being detected.

Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TEST_POINT_PCI_SPEED_INFO_LIB_H_
#define _TEST_POINT_PCI_SPEED_INFO_LIB_H_
#include <Uefi.h>

typedef enum {
  Ignore,     // Do not check link speed
  Gen1,       // 2.5 GT/s
  Gen2,       // 5.0 GT/s
  Gen3,       // 8.0 GT/s
  Gen4,       // 16.0 GT/s
  Gen5,       // 32.0 GT/s
  Gen6,       // 64.0 GT/s
  Unknown     // Unknown link speed
} PCIE_LINK_SPEED;

typedef struct {
  CHAR8              DeviceName[8];      // So it fits within the 64 bits of Additional Code 2 in section data
  BOOLEAN            IsFatal;
  UINTN              SegmentNumber;
  UINTN              BusNumber;
  UINTN              DeviceNumber;
  UINTN              FunctionNumber;
  PCIE_LINK_SPEED    MinimumLinkSpeed;
} DEVICE_PCI_INFO;

/**
  Returns a pointer to a static array of DEVICE_PCI_INFO structures and the length of the
  array.

  @param[out]       DevicesArray  Pointer to the head of an array of DEVICE_PCI_INFO structures.
                                  The caller shall not free this array.

  @retval           UINTN         Length of the returned array.

**/
UINTN
GetPciCheckDevices (
  OUT DEVICE_PCI_INFO  **DevicesArray
  );

#endif
