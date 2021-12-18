/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loader_3dsx;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class loader_3dsxLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "3DSX loader";
	}

	private final byte[] N3DSX_MAGIC = { 0x33, 0x44, 0x53, 0x58 }; // 3DSX
	private final int N3DSX_MAGIC_OFFSET = 0x00;
	private final int N3DSX_MAGIC_LENGTH = 4;

	private final int N3DSX_HEADER_OFFSET = 0x04;
	private final int N3DSX_HEADER_LENGTH = 2;

	private final int N3DSX_RELOC_HEADER_OFFSET = 0x06;
	private final int N3DSX_RELOC_HEADER_LENGTH = 2;
	
//	private final int N3DSX_FMT_VER_OFFSET = 0x08;
//	private final int N3DSX_FMT_VER_LENGTH = 4;

//	private final int N3DSX_FLAGS_OFFSET = 0x0c;
//	private final int N3DSX_FLAGS_LENGTH = 4;

	private final int N3DSX_CODE_SEG_SIZE_OFFSET = 0x10;
	private final int N3DSX_CODE_SEG_SIZE_LENGTH = 4;
	
	private final int N3DSX_RODATA_SEG_SIZE_OFFSET = 0x14;
	private final int N3DSX_RODATA_SEG_SIZE_LENGTH = 4;

	private final int N3DSX_DATA_SEG_SIZE_OFFSET = 0x18;
	private final int N3DSX_DATA_SEG_SIZE_LENGTH = 4;	

	private final int N3DSX_BSS_SEG_SIZE_OFFSET = 0x1c;
	private final int N3DSX_BSS_SEG_SIZE_LENGTH = 4;
	
	private final int LOAD_BASE_ADDR = 0x00108000;
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		byte[] magic = provider.readBytes(N3DSX_MAGIC_OFFSET, N3DSX_MAGIC_LENGTH);
		if (Arrays.equals(magic, N3DSX_MAGIC)) {
			LanguageCompilerSpecPair pair =
					new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default");
			loadSpecs.add(new LoadSpec(this, 0, pair, true));
		}
		return loadSpecs;		
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		try {
			FlatProgramAPI flatAPI = new FlatProgramAPI(program);		
			
			// header
			byte [] hdr_size_bytes = provider.readBytes(N3DSX_HEADER_OFFSET, N3DSX_HEADER_LENGTH);
			short hdr_size = ByteBuffer.wrap(hdr_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
			System.out.println(String.format("hdr_size: %04X", hdr_size));
			Address hdr_start_adr = flatAPI.toAddr(0x0);		
			MemoryBlock hdr_block = flatAPI.createMemoryBlock(
						"header", hdr_start_adr, 
						provider.readBytes(0, hdr_size), false);
			hdr_block.setRead(false);
			hdr_block.setWrite(false);
			hdr_block.setExecute(false);
			
			//size
			byte [] reloc_hdr_size_bytes = provider.readBytes(N3DSX_RELOC_HEADER_OFFSET, N3DSX_RELOC_HEADER_LENGTH);
			short reloc_hdr_size = ByteBuffer.wrap(reloc_hdr_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
			System.out.println(String.format("reloc_hdr_size: %04X", reloc_hdr_size));
	
			byte [] code_seg_size_bytes = provider.readBytes(N3DSX_CODE_SEG_SIZE_OFFSET, N3DSX_CODE_SEG_SIZE_LENGTH);		
			int code_seg_size = ByteBuffer.wrap(code_seg_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
			System.out.println(String.format("code_seg_size: %08X", code_seg_size));
			
			byte [] rodata_seg_size_bytes = provider.readBytes(N3DSX_RODATA_SEG_SIZE_OFFSET, N3DSX_RODATA_SEG_SIZE_LENGTH);
			int rodata_seg_size = ByteBuffer.wrap(rodata_seg_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
			System.out.println(String.format("rodata_seg_size: %08X", rodata_seg_size));
			
			byte [] data_seg_size_bytes = provider.readBytes(N3DSX_DATA_SEG_SIZE_OFFSET, N3DSX_DATA_SEG_SIZE_LENGTH);
			int data_seg_size = ByteBuffer.wrap(data_seg_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
			System.out.println(String.format("data_seg_size: %08X", data_seg_size));
	
			byte [] bss_seg_size_bytes = provider.readBytes(N3DSX_BSS_SEG_SIZE_OFFSET, N3DSX_BSS_SEG_SIZE_LENGTH);
			int bss_seg_size = ByteBuffer.wrap(bss_seg_size_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
			System.out.println(String.format("bss_seg_size: %08X", bss_seg_size));		
			
			//
			Memory memory = program.getMemory();
			
			// code seg
			int code_seg_load_addr = LOAD_BASE_ADDR;
			int code_seg_size_round = (code_seg_size + 0xFFF) & (~0xFFF);
			int file_offset = hdr_size + reloc_hdr_size * 3;
			
			System.out.println();
			System.out.println(String.format("code_seg_load_addr: %08X", code_seg_load_addr));
			System.out.println(String.format("code_seg_size_round: %08X", code_seg_size_round));
			System.out.println(String.format("file_offset: %08X", file_offset));
			
			Address code_seg_start_adr = flatAPI.toAddr(code_seg_load_addr);
			MemoryBlock code_seg_block = flatAPI.createMemoryBlock("code", code_seg_start_adr, null, code_seg_size_round, false);
			memory.convertToInitialized(code_seg_block, (byte) 0);
			code_seg_block.putBytes(code_seg_block.getStart(), provider.readBytes(file_offset, code_seg_size));
			
			code_seg_block.setRead(true);
			code_seg_block.setWrite(false);
			code_seg_block.setExecute(true);	
			
			// rodata seg
			int rodata_seg_load_addr = code_seg_load_addr + code_seg_size_round;
			int rodata_seg_size_round = (rodata_seg_size + 0xFFF) & (~0xFFF);
			file_offset += code_seg_size;
			
			System.out.println();
			System.out.println(String.format("rodata_seg_load_addr: %08X", rodata_seg_load_addr));
			System.out.println(String.format("rodata_seg_size_round: %08X", rodata_seg_size_round));
			System.out.println(String.format("file_offset: %08X", file_offset));		
			
			Address rodata_seg_start_adr = flatAPI.toAddr(rodata_seg_load_addr);		
			MemoryBlock rodata_seg_block = flatAPI.createMemoryBlock("rodata", rodata_seg_start_adr, null, rodata_seg_size_round, false);
			memory.convertToInitialized(rodata_seg_block, (byte) 0);
			rodata_seg_block.putBytes(rodata_seg_block.getStart(), provider.readBytes(file_offset, rodata_seg_size));
			
			rodata_seg_block.setRead(true);
			rodata_seg_block.setWrite(false);
			rodata_seg_block.setExecute(false);		
			
			// data seg
			int data_seg_load_addr = rodata_seg_load_addr + rodata_seg_size_round;
			int data_seg_size_round = (data_seg_size + 0xFFF) & (~0xFFF);		
			file_offset += rodata_seg_size;
			
			System.out.println();
			System.out.println(String.format("data_seg_load_addr: %08X", data_seg_load_addr));
			System.out.println(String.format("data_seg_size_round: %08X", data_seg_size_round));
			System.out.println(String.format("file_offset: %08X", file_offset));				
			
			Address data_seg_start_adr = flatAPI.toAddr(data_seg_load_addr);
			MemoryBlock data_seg_block = flatAPI.createMemoryBlock("data", data_seg_start_adr, null, data_seg_size_round, false);
			memory.convertToInitialized(data_seg_block, (byte) 0);
			data_seg_block.putBytes(data_seg_block.getStart(), provider.readBytes(file_offset, data_seg_size));
			
			data_seg_block.setRead(true);
			data_seg_block.setWrite(true);
			data_seg_block.setExecute(false);			
			
			// relocations
			int reloc_ptrs_offset = file_offset + (data_seg_size - bss_seg_size);
			System.out.println();
			System.out.println(String.format("relocs_ptr: %08X", reloc_ptrs_offset));
			
			MemoryBlock[] segments = {code_seg_block, rodata_seg_block, data_seg_block};
			
			for (int rel_table=0; rel_table<3; rel_table++) {
				System.out.println();
				System.out.println(String.format("\treloc_ptrs_offset: %08X", reloc_ptrs_offset));	
				
				MemoryBlock segment = segments[rel_table];
				int seg_offset = (int)segment.getStart().getOffset();			
				System.out.println(String.format("\tseg_offset: %08X", seg_offset));			
	
				byte[] abs_count_bytes = provider.readBytes(hdr_size + rel_table * 8, 4);
				int abs_count = ByteBuffer.wrap(abs_count_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
				System.out.println(String.format("\tabs_count: %04X", abs_count));	
	
				byte[] rel_count_bytes = provider.readBytes(hdr_size + rel_table * 8 + 4, 4);
				int rel_count = ByteBuffer.wrap(rel_count_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
				System.out.println(String.format("\trel_count: %04X", rel_count));
	
				int offset = reloc_ptrs_offset;
	
				// absolute relocations
				for (int i=0; i<abs_count; i++) {
					System.out.println();
					
					byte[] skip_bytes = provider.readBytes(offset, 2);
					short skip = ByteBuffer.wrap(skip_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
					System.out.println(String.format("\t\tskip: %04X", skip));
					
					byte[] patches_bytes = provider.readBytes(offset + 2, 2);
					short patches = ByteBuffer.wrap(patches_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
					System.out.println(String.format("\t\tpatches: %04X", patches));	
					
					seg_offset += skip * 4;
					
					for (int x=0; x<patches; x++) {
						System.out.println(String.format("\t\t\tseg_offset: %08X", seg_offset));
						
						byte[] addr_bytes = { 0x0, 0x0, 0x0, 0x0 };
						segment.getBytes(flatAPI.toAddr(seg_offset), addr_bytes, 0, 4);
						int addr = ByteBuffer.wrap(addr_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
						System.out.println(String.format("\t\t\taddr: %08X", addr));
	
						if (addr < code_seg_size_round) {
							addr = code_seg_load_addr + addr;
						} else if (addr < (code_seg_size_round + rodata_seg_size_round)) {
							addr = rodata_seg_load_addr + addr - code_seg_size_round;
						} else {
							addr = data_seg_load_addr + addr - (code_seg_size_round + rodata_seg_size_round);
						}
						System.out.println(String.format("\t\t\tmod_addr: %08X", addr));
	
						byte[] addr_buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(addr).array();
						segment.putBytes(flatAPI.toAddr(seg_offset), addr_buf);
						
						seg_offset += 4;
					}
	
					offset += 4;
				}
	
				// cross-segment relative relocations
				for (int i=0; i<rel_count; i++) {
					System.out.println();
					
					byte[] skip_bytes = provider.readBytes(offset, 2);
					short skip = ByteBuffer.wrap(skip_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
					System.out.println(String.format("\t\tskip: %04X", skip));
					
					byte[] patches_bytes = provider.readBytes(offset + 2, 2);
					short patches = ByteBuffer.wrap(patches_bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
					System.out.println(String.format("\t\tpatches: %04X", patches));	
					
					seg_offset += skip * 4;
					
					for (int x=0; x<patches; x++) {
						System.out.println(String.format("\t\t\tseg_offset: %08X", seg_offset));
						
						byte[] addr_bytes = { 0x0, 0x0, 0x0, 0x0 };
						segment.getBytes(flatAPI.toAddr(seg_offset), addr_bytes, 0, 4);
						int addr = ByteBuffer.wrap(addr_bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
						System.out.println(String.format("\t\t\taddr: %08X", addr));
	
						if (addr < code_seg_size_round) {
							addr = code_seg_load_addr + addr;
						} else if (addr < (code_seg_size_round + rodata_seg_size_round)) {
							addr = rodata_seg_load_addr + addr - code_seg_size_round;
						} else {
							addr = data_seg_load_addr + addr - (code_seg_size_round + rodata_seg_size_round);
						}
						System.out.println(String.format("\t\t\tmod_addr: %08X", addr));

						addr = seg_offset - addr;
						System.out.println(String.format("\t\t\trel_addr: %08X", addr));
	
						byte[] addr_buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(addr).array();
						segment.putBytes(flatAPI.toAddr(seg_offset), addr_buf);
						
						seg_offset += 4;
					}
	
					offset += 4;
				}
				
				reloc_ptrs_offset += abs_count * 4 + rel_count * 4;
			}

			// add entry point
			flatAPI.addEntryPoint(flatAPI.toAddr(code_seg_load_addr));
			flatAPI.disassemble(flatAPI.toAddr(code_seg_load_addr));
			
		} catch (Exception exc) {
			System.out.println(exc);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
