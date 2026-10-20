#pragma pack(push, 1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOFRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} section_header;
#pragma pack(pop)

typedef struct {
    uint32_t mask;
    const char *name;
} SectionFlagDesc;

static const SectionFlagDesc PE_SECTION_FLAGS[] = {
    {0x00000020, "CNT_CODE"},
    {0x00000040, "CNT_INITIALIZED_DATA"},
    {0x00000080, "CNT_UNINITIALIZED_DATA"},
    {0x00000200, "LNK_INFO"},
    {0x00000800, "LNK_REMOVE"},
    {0x00001000, "LNK_COMDAT"},
    {0x01000000, "LNK_NRELOC_OVFL"},
    {0x02000000, "MEM_DISCARDABLE"},
    {0x04000000, "MEM_NOT_CACHED"},
    {0x08000000, "MEM_NOT_PAGED"},
    {0x10000000, "MEM_SHARED"},
    {0x20000000, "MEM_EXECUTE"},
    {0x40000000, "MEM_READ"},
    {0x80000000, "MEM_WRITE"},
};

#define PE_FLAGS_COUNT (sizeof(PE_SECTION_FLAGS) / sizeof(PE_SECTION_FLAGS[0]))