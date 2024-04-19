## @file    BoardModulePkgHostTest.dsc
#
#  Copyright (c) Microsoft Corporation.
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
#  Description
#
##

[Defines]
PLATFORM_NAME           = BoardModulePkgHostTest
PLATFORM_GUID           = 67275336-A324-4F69-BD38-70A4C7898F06
PLATFORM_VERSION        = 0.1
DSC_SPECIFICATION       = 0x00010005
OUTPUT_DIRECTORY        = Build/BoardModulePkg/HostTest
SUPPORTED_ARCHITECTURES = IA32|X64|AARCH64
BUILD_TARGETS           = NOOPT
SKUID_IDENTIFIER        = DEFAULT

!include UnitTestFrameworkPkg/UnitTestFrameworkPkgHost.dsc.inc

[LibraryClasses]

[Components]
  #
  # List of Unit test packages
  #

  #
  # Build HOST_APPLICATION Libraries With GoogleTest
  #
  BoardModulePkg/Test/Mock/Library/GoogleTest/MockBiosIdLib/MockBiosIdLib.inf