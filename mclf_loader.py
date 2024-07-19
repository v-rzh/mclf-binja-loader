from binaryninja import *
from .tl_api_list import API_LIST

class MCLF_Loader(BinaryView):
    long_name = "MobiCore Loader Format"
    name = "MCLFLoader"
    magic_le = b"MCLF"
    magic_be = b"FLCM"
    MCLF_TEXT_DESCRIPTOR_OFFT = 128
    MCLF_MCLIB_ENTRY_FIELD = 0x108c

    def log(self, msg, error=False):
        msg = f"[MCLF Loader] {msg}"
        if error:
            log_error(msg)
        else:
            log_info(msg)

    def __init__(self, data):
        self.reader = BinaryReader(data, self.endianness)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

    @classmethod
    def is_valid_for_data(self, data):
        magic = data.read(0, 4)
        if magic == self.magic_le:
            self.endianness = Endianness.LittleEndian
            return True

        if magic == self.magic_be:
            self.endianness = Endianness.BigEndian
            return True

        return False

    def perform_get_default_endianness(self):
        return self.endianness

    def perform_get_address_size(self):
        return self.arch.address_size

    def perform_is_executable(self):
        return True

    def rename_mc_lib_func(self, function, mc_lib_num):
        if mc_lib_num in API_LIST:
            function.name = API_LIST[mc_lib_num]
        else:
            if mc_lib_num > 0x1000:
                function.name = f"drApiUnknown_{hex(mc_lib_num)}"
            else:
                function.name = f"tlApiUnknown_{hex(mc_lib_num)}"

    def resolve_mc_lib(self):
        """
        Ideally we want to use the get_reg_value_at method, however on Linux
        when that method is called in an analysis completion event handler,
        Binary Ninja freezes. Need to use this work around until that's fixed.
        It appears fetching mlil will cause a similar hang. 
        """
        for ref in self.get_code_refs(self.MCLF_MCLIB_ENTRY_FIELD):
            instructions = list(ref.function.instructions)
            for i in range(0, len(instructions)):
                inst = instructions[i]
                if inst[0][0].text == "bx" or inst[0][0].text == "blx":
                    for j in range(1, i+1):
                        inst = instructions[i-j]
                        if inst[0][0].text.startswith("mov"):
                            if inst[0][2].text == "r0":
                                if inst[0][-1].text.startswith("0x"):
                                    self.rename_mc_lib_func(ref.function, int(inst[0][-1].text, 16))
                                elif inst[0][-1].text.isnumeric():
                                    self.rename_mc_lib_func(ref.function, int(inst[0][-1].text))
                                break;

    def init(self):
        self.entry = self.reader.read32(0x44)
        self.version = self.reader.read32(0x4)
        self.text_va = self.reader.read32(0x30)
        self.text_len = self.reader.read32(0x34)
        self.data_va = self.reader.read32(0x38)
        self.data_len = self.reader.read32(0x3c)
        self.bss_len = self.reader.read32(0x40)

        if self.entry%4 == 1:
            self.arch = Architecture["thumb2"]
            self.platform = Platform["linux-thumb2"]
            self.entry -= 1
        else:
            self.arch = Architecture["armv7"]
            self.platform = Platform["linux-armv7"]

        typelib = TypeLibrary.new(self.arch, "mclf-structures")
        typelib.add_platform(self.platform)

        service_enum_type = EnumerationBuilder.create([], None, arch=self.arch)
        service_enum_type.append("SERVICE_TYPE_ILLEGAL", 0)
        service_enum_type.append("SERVICE_TYPE_DRIVER", 1)
        service_enum_type.append("SERVICE_TYPE_SP_TRUSTLET", 2)
        service_enum_type.append("SERVICE_TYPE_SYSTEM_TRUSTLET", 3)
        service_enum_type.append("SERVICE_TYPE_MIDDLEWARE", 4)
        service_enum_type.append("SERVICE_TYPE_LAST_ENTRY", 5)

        mem_enum_type = EnumerationBuilder.create([], None, arch=self.arch)
        mem_enum_type.append("MCLF_MEM_TYPE_INTERNAL_PREFERRED", 0)
        mem_enum_type.append("MCLF_MEM_TYPE_INTERNAL", 1)
        mem_enum_type.append("MCLF_MEM_TYPE_EXTERNAL", 2)
    
        flags_enum_type = EnumerationBuilder.create([], None, arch=self.arch)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT", 1)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE", 2)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE", 3)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_DEBUGGABLE", 4)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE", 5)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE", 6)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE", 7)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 8)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 9)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 10)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 11)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_DEBUGGABLE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 12)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 13)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 14)
        flags_enum_type.append("MC_SERVICE_HEADER_FLAGS_PERMANENT | MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE | MC_SERVICE_HEADER_FLAGS_DEBUGGABLE | MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT", 15)

        with StructureBuilder.builder(typelib, "segmentDescriptor_t") as struct_t:
            struct_t.append(Type.int(4, sign=False), "start")
            struct_t.append(Type.int(4, sign=False), "len")

        with StructureBuilder.builder(typelib, "mclfIntro_t") as struct_t:
            struct_t.append(Type.int(4, sign=False), "magic")
            struct_t.append(Type.int(4, sign=False), "version")

        with StructureBuilder.builder(typelib, "suidData_t") as struct_t:
            struct_t.append(Type.array(Type.int(1, sign=False), 12), "data")

        with StructureBuilder.builder(typelib, "mcSuid_t") as struct_t:
            struct_t.append(Type.int(4, sign=False), "sipId")
            struct_t.append(Type.structure_type(typelib.get_named_type("suidData_t")), "suidData")

        with StructureBuilder.builder(typelib, "mclfHeaderV2_t") as struct_t:
            struct_t.append(Type.structure_type(typelib.get_named_type("mclfIntro_t")), "intro")
            struct_t.append(flags_enum_type.immutable_copy(), "flags")
            struct_t.append(mem_enum_type.immutable_copy(), "memType")
            struct_t.append(service_enum_type.immutable_copy(), "serviceType")
            struct_t.append(Type.int(4, sign=False), "numInstances")
            struct_t.append(Type.array(Type.int(1, sign=False), 16), "uuid")
            struct_t.append(Type.int(4, sign=False), "driverId")
            struct_t.append(Type.int(4, sign=False), "numThreads")
            struct_t.append(Type.structure_type(typelib.get_named_type("segmentDescriptor_t")), "text")
            struct_t.append(Type.structure_type(typelib.get_named_type("segmentDescriptor_t")), "data")
            struct_t.append(Type.int(4, sign=False), "bssLen")
            struct_t.append(Type.int(4, sign=False), "entry")
            struct_t.append(Type.int(4, sign=False), "serviceVersion")

        with StructureBuilder.builder(typelib, "mclfHeaderV23_t") as struct_t:
            struct_t.append(Type.structure_type(typelib.get_named_type("mclfHeaderV2_t")), "mclfHeaderV2")
            struct_t.append(Type.structure_type(typelib.get_named_type("mcSuid_t")), "permittedSuid")
            struct_t.append(Type.int(4, sign=False), "permittedHwCfg")

        with StructureBuilder.builder(typelib, "mclfHeaderV24_t") as struct_t:
            struct_t.append(Type.structure_type(typelib.get_named_type("mclfHeaderV23_t")), "mclfHeaderV23")
            struct_t.append(Type.int(4, sign=False), "gp_level")
            struct_t.append(Type.int(4, sign=False), "attestationOffset")

        with StructureBuilder.builder(typelib, "heapSize_t") as struct_t:
            struct_t.append(Type.int(4, sign=False), "init")
            struct_t.append(Type.int(4, sign=False), "max")

        with StructureBuilder.builder(typelib, "mclfIMD_t") as struct_t:
            if self.version >= 0x20005:
                struct_t.append(Type.structure_type(typelib.get_named_type("heapSize_t")), "heapSize")
            else:
                struct_t.append(Type.structure_type(typelib.get_named_type("segmentDescriptor_t")),
                                "mcLibData")
            struct_t.append(Type.int(4, sign=False), "mcLibBase")

        with StructureBuilder.builder(typelib, "mclfTextHeader_t") as struct_t:
            struct_t.append(Type.int(4, sign=False), "version")
            struct_t.append(Type.int(4, sign=False), "textHeaderLen")
            struct_t.append(Type.int(4, sign=False), "requiredFeat")
            struct_t.append(Type.int(4, sign=False), "mcLibEntry")
            struct_t.append(Type.structure_type(typelib.get_named_type("mclfIMD_t")), "mcIMD")
            struct_t.append(Type.int(4, sign=False), "tlApiVers")
            struct_t.append(Type.int(4, sign=False), "drApiVers")
            struct_t.append(Type.int(4, sign=False), "ta_properties")


        self.add_user_segment(self.text_va, self.text_len, 0, self.text_len,
                              (SegmentFlag.SegmentContainsData |
                               SegmentFlag.SegmentContainsCode |
                               SegmentFlag.SegmentReadable |
                               SegmentFlag.SegmentExecutable))

        self.add_user_segment(self.data_va, self.data_len + self.bss_len, self.text_len,
                              self.data_len + self.bss_len,
                              (SegmentFlag.SegmentContainsData |
                               SegmentFlag.SegmentReadable))

        self.add_user_section(".text", self.text_va, self.text_len,
                              SectionSemantics.ReadOnlyCodeSectionSemantics)
        
        self.add_user_section(".data", self.data_va, self.data_len,
                              SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_user_section(".bss", self.data_va+self.data_len, self.bss_len,
                              SectionSemantics.ReadWriteDataSectionSemantics)

        if self.version == 0x20001 or self.version == 0x20002:
            self.define_user_data_var(self.text_va, self.import_library_type("mclfHeaderV2_t",
                                                                             typelib))
        elif self.version == 0x20003:
            self.define_user_data_var(self.text_va, self.import_library_type("mclfHeaderV23_t",
                                                                             typelib))
        elif self.version >= 0x20004:
            self.define_user_data_var(self.text_va, self.import_library_type("mclfHeaderV24_t",
                                                                             typelib))
        else:
            self.log(f"Invalid or unsupported MCLF version {hex(self.version)}", error=True)
            return False

        self.define_user_data_var(self.text_va+self.MCLF_TEXT_DESCRIPTOR_OFFT,
                                  self.import_library_type("mclfTextHeader_t", typelib))
        self.add_entry_point(self.entry)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.entry, "_start"))
        self.define_user_symbol(Symbol(SymbolType.DataSymbol, self.text_va, "__mclf_header"))
        self.define_user_symbol(Symbol(SymbolType.DataSymbol, self.text_va+self.MCLF_TEXT_DESCRIPTOR_OFFT,
                                       "__mclf_text_descriptor"))

        self.add_analysis_completion_event(self.resolve_mc_lib)

        return True

