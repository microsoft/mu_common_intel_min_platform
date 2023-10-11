/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/PciIo.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Library/PciSegmentLib.h>
#include <Library/PciSegmentInfoLib.h>
#include <IndustryStandard/Pci.h>
#include <Library/UefiLib.h>
#include <Library/TestPointPciSpeedInfoLib.h>

#pragma pack(1)

//
// Data region after PCI configuration header(for cardbus bridge)
//
typedef struct {
  UINT16  SubVendorId;  // Subsystem Vendor ID
  UINT16  SubSystemId;  // Subsystem ID
  UINT32  LegacyBase;   // Optional 16-Bit PC Card Legacy
  // Mode Base Address
  //
  UINT32  Data[46];
} PCI_CARDBUS_DATA;

typedef union {
  PCI_DEVICE_HEADER_TYPE_REGION Device;
  PCI_BRIDGE_CONTROL_REGISTER   Bridge;
  PCI_CARDBUS_CONTROL_REGISTER  CardBus;
} NON_COMMON_UNION;

typedef struct {
  PCI_DEVICE_INDEPENDENT_REGION Common;
  NON_COMMON_UNION              NonCommon;
  UINT32                        Data[48];
} PCI_CONFIG_SPACE;

// MU_CHANGE - BEGIN - TCBZ3541
typedef struct {
  UINT8 Segment;
  UINT8 Bus;
  UINT8 Device;
  UINT8 Function;
} EXEMPT_DEVICE;
// MU_CHANGE - END - TCBZ3541

#pragma pack()

VOID
DumpPciDevice (
  IN UINT8                             Bus,
  IN UINT8                             Device,
  IN UINT8                             Function,
  IN PCI_TYPE00                        *PciData
  )
{
//DEBUG ((DEBUG_INFO, "  00/00/00 : [0000][0000] [00|00|00] 00000000 00000000 00000000 00000000 00000000 00000000 0000\n"));
  DEBUG ((DEBUG_INFO, "  %02x/%02x/%02x :",
    Bus,
    Device,
    Function
    ));
  DEBUG ((DEBUG_INFO, " [%04x][%04x]",
    PciData->Hdr.VendorId,
    PciData->Hdr.DeviceId
    ));
  DEBUG ((DEBUG_INFO, " [%02x|%02x|%02x]",
    PciData->Hdr.ClassCode[2],
    PciData->Hdr.ClassCode[1],
    PciData->Hdr.ClassCode[0]
    ));
  DEBUG ((DEBUG_INFO, " %08x %08x %08x %08x %08x %08x",
    PciData->Device.Bar[0],
    PciData->Device.Bar[1],
    PciData->Device.Bar[2],
    PciData->Device.Bar[3],
    PciData->Device.Bar[4],
    PciData->Device.Bar[5]
    ));
  DEBUG ((DEBUG_INFO, " %04x\n",
    PciData->Hdr.Command
    ));
}

VOID
DumpPciBridge (
  IN UINT8                             Bus,
  IN UINT8                             Device,
  IN UINT8                             Function,
  IN PCI_TYPE01                        *PciData
  )
{
//DEBUG ((DEBUG_INFO, "  00/00/00*: [0000][0000] [00|00|00] 00000000 00000000 [00|00|00] [00:00] [0000:0000] [0000:0000] [00000000:00000000] [0000:0000] 0000   0000\n"));
  DEBUG ((DEBUG_INFO, "  %02x/%02x/%02x*:",
    Bus,
    Device,
    Function
    ));
  DEBUG ((DEBUG_INFO, " [%04x][%04x]",
    PciData->Hdr.VendorId,
    PciData->Hdr.DeviceId
    ));
  DEBUG ((DEBUG_INFO, " [%02x|%02x|%02x]",
    PciData->Hdr.ClassCode[2],
    PciData->Hdr.ClassCode[1],
    PciData->Hdr.ClassCode[0]
    ));
  DEBUG ((DEBUG_INFO, " %08x %08x",
    PciData->Bridge.Bar[0],
    PciData->Bridge.Bar[1]
    ));
  DEBUG ((DEBUG_INFO, " [%02x|%02x|%02x]",
    PciData->Bridge.PrimaryBus,
    PciData->Bridge.SecondaryBus,
    PciData->Bridge.SubordinateBus
    ));
  DEBUG ((DEBUG_INFO, " [%02x:%02x] [%04x:%04x] [%04x:%04x]",
    PciData->Bridge.IoBase,
    PciData->Bridge.IoLimit,
    PciData->Bridge.MemoryBase,
    PciData->Bridge.MemoryLimit,
    PciData->Bridge.PrefetchableMemoryBase,
    PciData->Bridge.PrefetchableMemoryLimit
    ));
  DEBUG ((DEBUG_INFO, " [%08x:%08x] [%04x:%04x]",
    PciData->Bridge.PrefetchableBaseUpper32,
    PciData->Bridge.PrefetchableLimitUpper32,
    PciData->Bridge.IoBaseUpper16,
    PciData->Bridge.IoLimitUpper16
    ));
  DEBUG ((DEBUG_INFO, " %04x  ",
    PciData->Bridge.BridgeControl
    ));
  DEBUG ((DEBUG_INFO, " %04x\n",
    PciData->Hdr.Command
    ));
}

/**
  This function gets the protocol interface from the given handle, and
  obtains its address space descriptors.

  @param[in] Handle          The PCI_ROOT_BRIDIGE_IO_PROTOCOL handle.
  @param[out] IoDev          Handle used to access configuration space of PCI device.
  @param[out] Descriptors    Points to the address space descriptors.

  @retval EFI_SUCCESS     The command completed successfully
**/
EFI_STATUS
PciGetProtocolAndResource (
  IN  EFI_HANDLE                            Handle,
  OUT EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL       **IoDev,
  OUT EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR     **Descriptors
  )
{
  EFI_STATUS  Status;

  //
  // Get inferface from protocol
  //
  Status = gBS->HandleProtocol (
                Handle,
                &gEfiPciRootBridgeIoProtocolGuid,
                (VOID**)IoDev
               );

  if (EFI_ERROR (Status)) {
    return Status;
  }
  //
  // Call Configuration() to get address space descriptors
  //
  Status = (*IoDev)->Configuration (*IoDev, (VOID**)Descriptors);
  if (Status == EFI_UNSUPPORTED) {
    *Descriptors = NULL;
    return EFI_SUCCESS;

  } else {
    return Status;
  }
}

/**
  This function get the next bus range of given address space descriptors.
  It also moves the pointer backward a node, to get prepared to be called
  again.

  @param[in, out] Descriptors Points to current position of a serial of address space
                              descriptors.
  @param[out] MinBus          The lower range of bus number.
  @param[out] MaxBus          The upper range of bus number.
  @param[out] IsEnd           Meet end of the serial of descriptors.

  @retval EFI_SUCCESS     The command completed successfully.
**/
EFI_STATUS
PciGetNextBusRange (
  IN OUT EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  **Descriptors,
  OUT    UINT16                             *MinBus,
  OUT    UINT16                             *MaxBus,
  OUT    BOOLEAN                            *IsEnd
  )
{
  *IsEnd = FALSE;

  //
  // When *Descriptors is NULL, Configuration() is not implemented, so assume
  // range is 0~PCI_MAX_BUS
  //
  if ((*Descriptors) == NULL) {
    *MinBus = 0;
    *MaxBus = PCI_MAX_BUS;
    return EFI_SUCCESS;
  }
  //
  // *Descriptors points to one or more address space descriptors, which
  // ends with a end tagged descriptor. Examine each of the descriptors,
  // if a bus typed one is found and its bus range covers bus, this handle
  // is the handle we are looking for.
  //

  while ((*Descriptors)->Desc != ACPI_END_TAG_DESCRIPTOR) {
    if ((*Descriptors)->ResType == ACPI_ADDRESS_SPACE_TYPE_BUS) {
      *MinBus = (UINT16) (*Descriptors)->AddrRangeMin;
      *MaxBus = (UINT16) (*Descriptors)->AddrRangeMax;
      (*Descriptors)++;
      return (EFI_SUCCESS);
    }

    (*Descriptors)++;
  }

  if ((*Descriptors)->Desc == ACPI_END_TAG_DESCRIPTOR) {
    *IsEnd = TRUE;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointCheckPciResource (
  VOID
  )
{
  UINT16                            Bus;
  UINT16                            Device;
  UINT16                            Func;
  UINT64                            Address;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL   *IoDev;
  EFI_STATUS                        Status;
  PCI_TYPE00                        PciData;
  UINTN                             Index;
  EFI_HANDLE                        *HandleBuf;
  UINTN                             HandleCount;
  EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *Descriptors;
  UINT16                            MinBus;
  UINT16                            MaxBus;
  BOOLEAN                           IsEnd;

  DEBUG ((DEBUG_INFO, "==== TestPointCheckPciResource - Enter\n"));
  HandleBuf = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciRootBridgeIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuf
                  );
  if (EFI_ERROR (Status)) {
    goto Done ;
  }

  DEBUG ((DEBUG_INFO, "  B  D  F*    VID   DID   Class[CSP]   Bar0     Bar1    Bus[PSS]   Io[BL]  Memory[BL]"));
  DEBUG ((DEBUG_INFO, " PMemory[BL]    PMemoryU[BL]       IoU[BL]   BriCtl Command\n"));

  DEBUG ((DEBUG_INFO, "  B  D  F     VID   DID   Class[CSP]   Bar0     Bar1     Bar2     Bar3     Bar4     Bar5   Command\n"));

  for (Index = 0; Index < HandleCount; Index++) {
    Status = PciGetProtocolAndResource (
               HandleBuf[Index],
               &IoDev,
               &Descriptors
               );
    while (TRUE) {
      Status = PciGetNextBusRange (&Descriptors, &MinBus, &MaxBus, &IsEnd);
      if (EFI_ERROR (Status)) {
        goto Done;
      }

      if (IsEnd) {
        break;
      }

      for (Bus = MinBus; Bus <= MaxBus; Bus++) {
        //
        // For each devices, enumerate all functions it contains
        //
        for (Device = 0; Device <= PCI_MAX_DEVICE; Device++) {
          //
          // For each function, read its configuration space and print summary
          //
          for (Func = 0; Func <= PCI_MAX_FUNC; Func++) {
            Address = EFI_PCI_ADDRESS (Bus, Device, Func, 0);
            IoDev->Pci.Read (
                         IoDev,
                         EfiPciWidthUint16,
                         Address,
                         1,
                         &PciData.Hdr.VendorId
                         );

            //
            // If VendorId = 0xffff, there does not exist a device at this
            // location. For each device, if there is any function on it,
            // there must be 1 function at Function 0. So if Func = 0, there
            // will be no more functions in the same device, so we can break
            // loop to deal with the next device.
            //
            if (PciData.Hdr.VendorId == 0xffff && Func == 0) {
              break;
            }

            if (PciData.Hdr.VendorId != 0xffff) {
              IoDev->Pci.Read (
                           IoDev,
                           EfiPciWidthUint32,
                           Address,
                           sizeof (PciData) / sizeof (UINT32),
                           &PciData
                           );

              if (IS_PCI_BRIDGE(&PciData)) {
                // Bridge
                DumpPciBridge ((UINT8)Bus, (UINT8)Device, (UINT8)Func, (PCI_TYPE01 *)&PciData);
              } else if (IS_CARDBUS_BRIDGE(&PciData)) {
                // CardBus Bridge
              } else {
                // Device
                DumpPciDevice ((UINT8)Bus, (UINT8)Device, (UINT8)Func, &PciData);
              }

              //
              // If this is not a multi-function device, we can leave the loop
              // to deal with the next device.
              //
              if (Func == 0 && ((PciData.Hdr.HeaderType & HEADER_TYPE_MULTI_FUNCTION) == 0x00)) {
                break;
              }
            }
          }
        }
      }
      //
      // If Descriptor is NULL, Configuration() returns EFI_UNSUPPRORED,
      // we assume the bus range is 0~PCI_MAX_BUS. After enumerated all
      // devices on all bus, we can leave loop.
      //
      if (Descriptors == NULL) {
        break;
      }
    }
  }

Done:
  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  DEBUG ((DEBUG_INFO, "==== TestPointCheckPciResource - Exit\n"));

  if (EFI_ERROR(Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
      TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED_ERROR_CODE \
        TEST_POINT_PCI_ENUMERATION_DONE \
        TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_RESOURCE_ALLOCATED_ERROR_STRING
      );
  }

  return Status;
}

EFI_STATUS
TestPointCheckPciBusMaster (
  VOID
  )
{
  UINTN             Segment;
  UINTN             SegmentCount;
  UINTN             Bus;
  UINTN             Device;
  UINTN             Function;
  UINT16            VendorId;
  UINT16            Command;
  UINT8             HeaderType;
  EFI_STATUS        Status;
  PCI_SEGMENT_INFO  *PciSegmentInfo;
  // MU_CHANGE - BEGIN - TCBZ3541
  EXEMPT_DEVICE     *ExemptDevicePcdPtr;
  BOOLEAN           ExemptDeviceFound;
  UINTN             Index;
  // MU_CHANGE - END - TCBZ3541

  PciSegmentInfo = GetPciSegmentInfo (&SegmentCount);
  if (PciSegmentInfo == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = EFI_SUCCESS;
  for (Segment = 0; Segment < SegmentCount; Segment++) {
    for (Bus = PciSegmentInfo[Segment].StartBusNumber; Bus <= PciSegmentInfo[Segment].EndBusNumber; Bus++) {
      for (Device = 0; Device <= 0x1F; Device++) {
        for (Function = 0; Function <= 0x7; Function++) {
          // MU_CHANGE - BEGIN - TCBZ3541
          //
          // Some platforms have devices which do not expose any additional
          // risk of DMA attacks but are not able to be turned off.  Allow
          // the platform to define these devices and do not record errors
          // for these devices.
          //
          ExemptDevicePcdPtr = (EXEMPT_DEVICE *) PcdGetPtr (PcdTestPointIbvPlatformExemptPciBme);
          ExemptDeviceFound = FALSE;
          for (Index = 0; Index < (PcdGetSize (PcdTestPointIbvPlatformExemptPciBme) / sizeof (EXEMPT_DEVICE)); Index++) {
            if (Segment == ExemptDevicePcdPtr[Index].Segment
                && Bus == ExemptDevicePcdPtr[Index].Bus
                && Device == ExemptDevicePcdPtr[Index].Device
                && Function == ExemptDevicePcdPtr[Index].Function) {
              ExemptDeviceFound = TRUE;
            }
          }

          if (ExemptDeviceFound) {
            continue;
          }
          // MU_CHANGE - END - TCBZ3541

          VendorId = PciSegmentRead16 (PCI_SEGMENT_LIB_ADDRESS(PciSegmentInfo[Segment].SegmentNumber, Bus, Device, Function, PCI_VENDOR_ID_OFFSET));
          //
          // If VendorId = 0xffff, there does not exist a device at this
          // location. For each device, if there is any function on it,
          // there must be 1 function at Function 0. So if Func = 0, there
          // will be no more functions in the same device, so we can break
          // loop to deal with the next device.
          //
          if (VendorId == 0xffff && Function == 0) {
            break;
          }

          if (VendorId != 0xffff) {
            Command = PciSegmentRead16 (PCI_SEGMENT_LIB_ADDRESS(Segment, Bus, Device, Function, PCI_COMMAND_OFFSET));
            if ((Command & EFI_PCI_COMMAND_BUS_MASTER) != 0) {
              DEBUG ((DEBUG_INFO, "PCI BME enabled (S%04x.B%02x.D%02x.F%x - %04x)\n", Segment, Bus, Device, Function, Command));
              TestPointLibAppendErrorString (
                PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
                TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
                TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED_ERROR_CODE \
                  TEST_POINT_PCI_ENUMERATION_DONE \
                  TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_BUS_MASTER_DISABLED_ERROR_STRING
                );
              Status = EFI_INVALID_PARAMETER;
            }

            //
            // If this is not a multi-function device, we can leave the loop
            // to deal with the next device.
            //
            HeaderType = PciSegmentRead8 (PCI_SEGMENT_LIB_ADDRESS(Segment, Bus, Device, Function, PCI_HEADER_TYPE_OFFSET));
            if (Function == 0 && ((HeaderType & HEADER_TYPE_MULTI_FUNCTION) == 0x00)) {
              break;
            }
          }
        }
      }
    }
  }

  return Status;
}


/**
 Find a target capability block in PCI configuration space.

 @param[in]  PciIoDev           Pointer to EFI_PCI_IO_PROTOCOL
 @param[in]  DesiredPciCapId    Desired PCI capability ID
 @param[out] Offset             Pointer to Offset of Capability ID

 @retval EFI_SUCCESS            Capability was located and offset stored in *Offset
 @retval EFI_NOT_FOUND          Did not find the desired PCI capability
**/
EFI_STATUS
FindPciCapabilityPtr (
  IN EFI_PCI_IO_PROTOCOL *PciIoDev,
  IN UINT8 DesiredPciCapId,
  OUT UINT32 *Offset
  )
{
  UINT8 PciCapNext;
  UINT8 PciCapId;
  UINT16 PciCapHeader = 0;

  PciCapId = 0;
  PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint8, PCI_CAPBILITY_POINTER_OFFSET, 1, &PciCapNext);
  while ((PciCapId != DesiredPciCapId) && (PciCapNext != 0)) {
    PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint16, PciCapNext, 1, &PciCapHeader);
    PciCapId = PciCapHeader & 0xff;
    if (PciCapId == DesiredPciCapId) {
      break;
    }
    PciCapNext = PciCapHeader >> 8;
  }

  if (PciCapId == DesiredPciCapId) {
    *Offset = PciCapNext;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

/**
 Test that required devices have trained to the required link speed.

 @retval EFI_SUCCESS            Test was performed and flagged as verified or error logged.
 @retval EFI_NOT_FOUND          GetPciCheckDevices returned 0 or a NULL pointer, or Allocating array failed.
 @retval EFI_DEVICE_ERROR       A PCI device was not found or was not up at the required speed.
**/
EFI_STATUS
EFIAPI
TestPointCheckPciSpeed (
  VOID
  )
{
  EFI_STATUS                Status;
  UINTN                     ProtocolCount;
  UINTN                     Seg;
  UINTN                     Bus;
  UINTN                     Dev;
  UINTN                     Fun;
  UINTN                     NumDevices;
  UINTN                     OuterLoop;
  UINTN                     InnerLoop;
  EFI_PCI_IO_PROTOCOL       *PciIoDev;
  PCI_REG_PCIE_LINK_STATUS  PcieLinkStatusReg;
  UINT32                    Offset;

  // To store protocols
  EFI_PCI_IO_PROTOCOL  **ProtocolList = NULL;

  // Array of pci info pointers. The ARRAY is freed, but the individual struct pointers pointed to
  // from within the array are not. This is to make the structs within the TestPointPciSpeedInfoLib
  // simpler by declaring them as globals
  DEVICE_PCI_INFO  *Devices = NULL;

  // Array parallel to Devices which we will use to check off which devices we've found
  BOOLEAN  *DeviceFound    = NULL;
  BOOLEAN  AllDevicesFound = FALSE;

  // Get a pointer to the array of data structures
  NumDevices = GetPciCheckDevices (&Devices);

  // Array to track which devices we've found
  DeviceFound = AllocateZeroPool (sizeof (BOOLEAN) * NumDevices);

  // Ensure that all necessary pointers have been populated, abort to cleanup if not
  if ((Devices == NULL) || (DeviceFound == NULL) || (NumDevices == 0) ||
      EFI_ERROR (EfiLocateProtocolBuffer (&gEfiPciIoProtocolGuid, &ProtocolCount, (VOID *)&ProtocolList)))
  {
    Status = EFI_NOT_FOUND;
    goto Cleanup;
  }

  // For each device protocol found...
  for (OuterLoop = 0; OuterLoop < ProtocolCount; OuterLoop++) {
    PciIoDev = ProtocolList[OuterLoop];

    // Get device location
    if (EFI_ERROR (PciIoDev->GetLocation (PciIoDev, &Seg, &Bus, &Dev, &Fun))) {
      continue;
    }

    // For each device supplied by TestPointPciSpeedInfoLib...
    for (InnerLoop = 0; InnerLoop < NumDevices; InnerLoop++) {
      // Check if that device matches the current protocol in OuterLoop
      if ((Seg == Devices[InnerLoop].SegmentNumber) && (Bus == Devices[InnerLoop].BusNumber) &&
          (Dev == Devices[InnerLoop].DeviceNumber) && (Fun == Devices[InnerLoop].FunctionNumber))
      {
        // Also check link speed.
        Status = FindPciCapabilityPtr (
                   PciIoDev,
                   EFI_PCI_CAPABILITY_ID_PCIEXP,
                   &Offset
                   );
        ASSERT_EFI_ERROR (Status);

        Offset += OFFSET_OF (PCI_CAPABILITY_PCIEXP, LinkStatus);
        PciIoDev->Pci.Read (PciIoDev, EfiPciIoWidthUint16, Offset, 1, &PcieLinkStatusReg.Uint16);
        DEBUG ((DEBUG_INFO, "[%a] LinkStatusReg = %04x\n", __FUNCTION__, PcieLinkStatusReg.Uint16));
        if (PcieLinkStatusReg.Bits.CurrentLinkSpeed >= Devices[InnerLoop].MinimumLinkSpeed) {
          // If it matches, check it off in the parallel array
          DeviceFound[InnerLoop] = TRUE;
        }
      }
    }
  }

  // For each device supplied by TestPointPciSpeedInfoLib...
  AllDevicesFound = TRUE;
  for (OuterLoop = 0; OuterLoop < NumDevices; OuterLoop++) {
    // Check if the previous loop found that device
    if (DeviceFound[OuterLoop] == FALSE) {
      AllDevicesFound = FALSE;

      DEBUG ((
        DEBUG_INFO,
        "%a - %a not found. Expected Segment: %d  Bus: %d  Device: %d  Function: %d, MinimumLinkSpeed: %d\n",
        __FUNCTION__,
        Devices[OuterLoop].DeviceName,
        Devices[OuterLoop].SegmentNumber,
        Devices[OuterLoop].BusNumber,
        Devices[OuterLoop].DeviceNumber,
        Devices[OuterLoop].FunctionNumber,
        Devices[OuterLoop].MinimumLinkSpeed
        ));
    }
  }

  if (AllDevicesFound == TRUE) {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_DEVICE_ERROR;
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      TEST_POINT_IMPLEMENTATION_ID_PLATFORM_DXE,
      TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED_ERROR_CODE \
      TEST_POINT_PCI_ENUMERATION_DONE \
      TEST_POINT_BYTE3_PCI_ENUMERATION_DONE_PCIE_GEN_SPEED_ERROR_STRING
      );
  }

Cleanup:
  // Make sure everything is freed
  if (DeviceFound != NULL) {
    FreePool (DeviceFound);
  }

  if (ProtocolList != NULL) {
    FreePool (ProtocolList);
  }

  return Status;
}
