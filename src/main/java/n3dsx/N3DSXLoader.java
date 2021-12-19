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
package n3dsx;

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
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class N3DSXLoader extends AbstractLibrarySupportLoader {

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
	
	private short readShort(ByteProvider provider, int offset, int length) throws IOException {
		byte[] bytes = provider.readBytes(offset, length);
		return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort();
	}
	
	private int readInt(ByteProvider provider, int offset, int length) throws IOException {
		byte[] bytes = provider.readBytes(offset, length);
		return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}
	
	private void configPermissions(MemoryBlock block, byte perms) {
		block.setRead(((perms >> 2) & 1) == 1);
		block.setWrite(((perms >> 1) & 1) == 1);
		block.setExecute((perms & 1) == 1);
	}
	
	private MemoryBlock createSegment(
			FlatProgramAPI flatAPI, ByteProvider provider, Program program, 
			String name, int startAddr, int offset, int length, boolean pad, byte perms) throws Exception {
		int lengthPadded = (length + 0xFFF) & (~0xFFF);
		MemoryBlock block = flatAPI.createMemoryBlock(
				name, flatAPI.toAddr(startAddr), null, pad ? lengthPadded : length, false);
		program.getMemory().convertToInitialized(block, (byte)0x0);
		block.putBytes(block.getStart(), provider.readBytes(offset, length));
		configPermissions(block, perms);
		return block;
	}

	private int[] fixupReocations(
			FlatProgramAPI flatAPI, ByteProvider provider,
			MemoryBlock codeSeg, MemoryBlock rodataSeg, MemoryBlock dataSeg,
			int relocsNum, int fileOffset, MemoryBlock segment, int segOffset, boolean relative) throws Exception {
		for (int i=0; i<relocsNum; i++) {
			short skipWordsNum = readShort(provider, fileOffset, 2);
			short patchWordsNum = readShort(provider, fileOffset + 2, 2);
			
			System.out.println("\t\t====================");
			System.out.println(String.format("\t\tskip_words_num: %04x", skipWordsNum));					
			System.out.println(String.format("\t\tpatch_words_num: %04x", patchWordsNum));	
			
			segOffset += skipWordsNum * 4;
			
			for (int j=0; j<patchWordsNum; j++) {
				System.out.println("\t\t\t====================");
				System.out.println(String.format("\t\t\tseg_offset: %08x", segOffset));
				
				// read addr pointer at seg offset
				byte[] addrBytes = { 0x0, 0x0, 0x0, 0x0 };
				segment.getBytes(flatAPI.toAddr(segOffset), addrBytes, 0, 4);
				int addr = ByteBuffer.wrap(addrBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
				System.out.println(String.format("\t\t\taddr: %08x", addr));

				// depending on the orig addr loc, relocate to corresponding segment
				if (addr < codeSeg.getSize()) {
					addr = (int)codeSeg.getStart().getOffset() + addr;
				} else if (addr < (codeSeg.getSize() + rodataSeg.getSize())) {
					addr = (int)rodataSeg.getStart().getOffset() + addr - (int)codeSeg.getSize();
				} else {
					addr = (int)dataSeg.getStart().getOffset() + addr - (int)(codeSeg.getSize() + rodataSeg.getSize());
				}
				System.out.println(String.format("\t\t\tfix_addr: %08x", addr));
				
				if (relative) {
					addr = segOffset - addr;
					System.out.println(String.format("\t\t\trel_addr: %08x", addr));
				}

				// convert addr back to bytes and apply the fix
				addrBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(addr).array();
				segment.putBytes(flatAPI.toAddr(segOffset), addrBytes);
				
				segOffset += 4;
			}
			fileOffset += 4;
		}		
		return new int[] { fileOffset, segOffset };
	}
	
	@Override
	public String getName() {
		return "Nintendo 3DS Homebrew Application (3DSX) loader";
	}	
	
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
			// sizes
			short hdrSize = readShort(provider, N3DSX_HEADER_OFFSET, N3DSX_HEADER_LENGTH);
			short relocHdrSize = readShort(provider, N3DSX_RELOC_HEADER_OFFSET, N3DSX_RELOC_HEADER_LENGTH);
			int codeSegSize = readInt(provider, N3DSX_CODE_SEG_SIZE_OFFSET, N3DSX_CODE_SEG_SIZE_LENGTH);
			int rodataSegSize = readInt(provider, N3DSX_RODATA_SEG_SIZE_OFFSET, N3DSX_RODATA_SEG_SIZE_LENGTH);
			int dataSegSize = readInt(provider, N3DSX_DATA_SEG_SIZE_OFFSET, N3DSX_DATA_SEG_SIZE_LENGTH);
			int bssSegSize = readInt(provider, N3DSX_BSS_SEG_SIZE_OFFSET, N3DSX_BSS_SEG_SIZE_LENGTH);
			
			System.out.println("====================");
			System.out.println(String.format("hdr_size: %04x", hdrSize));
			System.out.println(String.format("reloc_hdr_size: %04x", relocHdrSize));
			System.out.println(String.format("code_seg_size: %08x", codeSegSize));
			System.out.println(String.format("rodata_seg_size: %08x", rodataSegSize));
			System.out.println(String.format("data_seg_size: %08x", dataSegSize));
			System.out.println(String.format("bss_seg_size: %08x", bssSegSize));	

			FlatProgramAPI flatAPI = new FlatProgramAPI(program);		
			
			// header seg
			createSegment(flatAPI, provider, program, 
					"header", 0x0, 0x0, hdrSize, false, (byte)0x4); //r--
			
			// code seg
			int loadAddr = LOAD_BASE_ADDR;
			int fileOffset = hdrSize + relocHdrSize * 3; // code, rodata, data
			MemoryBlock codeSeg = createSegment(flatAPI, provider, program, 
					"code", loadAddr, fileOffset, codeSegSize, true, (byte)0x5); //r-x
			
			// rodata seg
			loadAddr = (int)codeSeg.getEnd().getOffset() + 0x1;
			fileOffset += codeSegSize;
			MemoryBlock rodataSeg = createSegment(flatAPI, provider, program, 
					"rodata", loadAddr, fileOffset, rodataSegSize, true, (byte)0x4); //r--			
			
			// data seg
			loadAddr = (int)rodataSeg.getEnd().getOffset() + 0x1;
			fileOffset += rodataSegSize;
			MemoryBlock dataSeg = createSegment(flatAPI, provider, program, 
					"data", loadAddr, fileOffset, dataSegSize, true, (byte)0x6); //rw-
			
			System.out.println("====================");
			System.out.println(String.format("code_seg_addr: %08x", codeSeg.getStart().getOffset()));
			System.out.println(String.format("code_seg_size: %08x", codeSeg.getSize()));
			System.out.println(String.format("rodata_seg_addr: %08x", rodataSeg.getStart().getOffset()));
			System.out.println(String.format("rodata_seg_size: %08x", rodataSeg.getSize()));
			System.out.println(String.format("data_seg_addr: %08x", dataSeg.getStart().getOffset()));
			System.out.println(String.format("data_seg_size: %08x", dataSeg.getSize()));
			
			// fix relocations
			System.out.println("====================");
			fileOffset += (dataSegSize - bssSegSize);
			System.out.println(String.format("reloc_ptrs_offset: %08x", fileOffset));
			
			MemoryBlock[] segments = { codeSeg, rodataSeg, dataSeg };			

			for (int relTable=0; relTable<3; relTable++) {
				MemoryBlock segment = segments[relTable];
				int segOffset = (int)segment.getStart().getOffset();
				int absRelocsNum = readInt(provider, hdrSize + relTable * 8, 4);
				int relRelocsNum = readInt(provider, hdrSize + relTable * 8 + 4, 4);

				System.out.println("\t====================");
				System.out.println(String.format("\treloc_ptrs_offset: %08x", fileOffset));	
				System.out.println(String.format("\tseg_offset: %08x", segOffset));
				System.out.println(String.format("\tabs_count: %04x", absRelocsNum));
				System.out.println(String.format("\trel_count: %04x", relRelocsNum));

				int offset = fileOffset;
	
				// absolute relocations
				int[] offsets = fixupReocations(
						flatAPI, provider,
						codeSeg, rodataSeg, dataSeg,
						absRelocsNum, offset, segment, segOffset, false);
				
				offset = offsets[0];
				segOffset = offsets[1];
				
				System.out.println("\t====================");
				System.out.println("\tafter abs relocs");
				System.out.println(String.format("\toffset: %08x", offset));
				System.out.println(String.format("\tseg_offset: %08x", segOffset));
				
				// cross-segment relative relocations
				offsets = fixupReocations(
						flatAPI, provider,
						codeSeg, rodataSeg, dataSeg,
						relRelocsNum, offset, segment, segOffset, true);
				
				offset = offsets[0];
				segOffset = offsets[1];
				
				System.out.println("\t====================");
				System.out.println("\tafter rel relocs");
				System.out.println(String.format("\toffset: %08x", offset));
				System.out.println(String.format("\tseg_offset: %08x", segOffset));				

				// continue with relocations for next segment
				fileOffset += absRelocsNum * 4 + relRelocsNum * 4;
			}

			// add entry point
			flatAPI.addEntryPoint(codeSeg.getStart());
			flatAPI.disassemble(codeSeg.getStart());
			
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
