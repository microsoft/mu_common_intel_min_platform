/** @file MockBiosIdLib.cpp
  Google Test mocks for BiosIdLib

  Copyright (c) Microsoft Corporation.
  Your use of this software is governed by the terms of the Microsoft agreement under which you obtained the software.
**/

#include <GoogleTest/Library/MockBiosIdLib.h>

MOCK_INTERFACE_DEFINITION (MockBiosIdLib);
MOCK_FUNCTION_DEFINITION (MockBiosIdLib, GetBiosId, 1, EFIAPI);
