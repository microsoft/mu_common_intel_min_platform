/**@file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __VARIABLE_H__
#define __VARIABLE_H__

extern EFI_GUID gEfiVariableGuid;
extern EFI_GUID gEfiAuthenticatedVariableGuid;

///
/// Alignment of variable name and data, according to the architecture:
/// * For IA-32 and Intel(R) 64 architectures: 1.
/// * For IA-64 architecture: 8.
///
#if defined (MDE_CPU_IPF)
#define ALIGNMENT         8
#else
#define ALIGNMENT         1
#endif

//
// GET_PAD_SIZE calculates the miminal pad bytes needed to make the current pad size satisfy the alignment requirement.
//
#if (ALIGNMENT == 1)
#define GET_PAD_SIZE(a) (0)
#else
#define GET_PAD_SIZE(a) (((~a) + 1) & (ALIGNMENT - 1))
#endif

///
/// Alignment of Variable Data Header in Variable Store region.
///
#define HEADER_ALIGNMENT  4
#define HEADER_ALIGN(Header)  (((UINTN) (Header) + HEADER_ALIGNMENT - 1) & (~(HEADER_ALIGNMENT - 1)))

///
/// Status of Variable Store Region.
///
typedef enum {
  EfiRaw,
  EfiValid,
  EfiInvalid,
  EfiUnknown
} VARIABLE_STORE_STATUS;

#pragma pack(1)

///
/// Variable Store Header Format and State.
///
#define VARIABLE_STORE_FORMATTED          0x5a
#define VARIABLE_STORE_HEALTHY            0xfe

///
/// Variable Store region header.
///
typedef struct {
  ///
  /// Variable store region signature.
  ///
  EFI_GUID  Signature;
  ///
  /// Size of entire variable store, 
  /// including size of variable store header but not including the size of FvHeader.
  ///
  UINT32  Size;
  ///
  /// Variable region format state.
  ///
  UINT8   Format;
  ///
  /// Variable region healthy state.
  ///
  UINT8   State;
  UINT16  Reserved;
  UINT32  Reserved1;
} VARIABLE_STORE_HEADER;

///
/// Variable data start flag.
///
#define VARIABLE_DATA                     0x55AA

///
/// Variable State flags.
///
#define VAR_IN_DELETED_TRANSITION     0xfe  ///< Variable is in obsolete transition.
#define VAR_DELETED                   0xfd  ///< Variable is obsolete.
#define VAR_HEADER_VALID_ONLY         0x7f  ///< Variable header has been valid.
#define VAR_ADDED                     0x3f  ///< Variable has been completely added.

///
/// Single Variable Data Header Structure.
///
typedef struct {
  ///
  /// Variable Data Start Flag.
  ///
  UINT16      StartId;
  ///
  /// Variable State defined above.
  ///
  UINT8       State;
  UINT8       Reserved;
  ///
  /// Attributes of variable defined in UEFI specification.
  ///
  UINT32      Attributes;
  ///
  /// Size of variable null-terminated Unicode string name.
  ///
  UINT32      NameSize;
  ///
  /// Size of the variable data without this header.
  ///
  UINT32      DataSize;
  ///
  /// A unique identifier for the vendor that produces and consumes this varaible.
  ///
  EFI_GUID    VendorGuid;
} VARIABLE_HEADER;

///
/// Single Variable Data Header Structure for Auth variable.
///
typedef struct {
  ///
  /// Variable Data Start Flag.
  ///
  UINT16      StartId;
  ///
  /// Variable State defined above.
  ///
  UINT8       State;
  UINT8       Reserved;
  ///
  /// Attributes of variable defined in UEFI specification.
  ///
  UINT32      Attributes;
  ///
  /// Associated monotonic count value against replay attack.
  ///
  UINT64      MonotonicCount;
  ///
  /// Associated TimeStamp value against replay attack. 
  ///
  EFI_TIME    TimeStamp;
  ///
  /// Index of associated public key in database.
  ///
  UINT32      PubKeyIndex;
  ///
  /// Size of variable null-terminated Unicode string name.
  ///
  UINT32      NameSize;
  ///
  /// Size of the variable data without this header.
  ///
  UINT32      DataSize;
  ///
  /// A unique identifier for the vendor that produces and consumes this varaible.
  ///
  EFI_GUID    VendorGuid;
} AUTHENTICATED_VARIABLE_HEADER;

#pragma pack()

#endif
