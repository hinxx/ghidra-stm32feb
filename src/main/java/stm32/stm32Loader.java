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

// This is for STM32F103x clone found in eBike LSW1108-01-01E controller. See 75-STM32FEBKC6T6.pdf datasheet.
// STM32FEBKC6T6
// Flash: 32 kB
// SRAM: 10 kB
// Timers: 2
// Adv timers: 1
// SPI: 1
// I2C: 1
// USART: 2
// USB: 1
// CAN: 1
// GPIOs: 32
// ADC: 2 (10 channels)

package stm32;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class stm32Loader extends AbstractLibrarySupportLoader {

    private static class RegLabel {
        String label;
        int addr;
        private RegLabel(String label, int addr) {
            this.label = label;
            this.addr = addr;
        }

    }

    private static class STM32InterruptVector{
        String name;
        int addr;
        private STM32InterruptVector(String name, int addr)
        {
            this.name = name;
            this.addr = addr;
        }
    }

    private static final STM32InterruptVector [] STM32IVT = {
        new STM32InterruptVector("RESET",           0x4),
        new STM32InterruptVector("NMI",             0x8),
        new STM32InterruptVector("HardFault",       0xC),
        new STM32InterruptVector("MemManage",       0x10),
        new STM32InterruptVector("BusFault",        0x14),
        new STM32InterruptVector("UsageFault",      0x18),
        new STM32InterruptVector("SVCall",          0x2C),
        new STM32InterruptVector("Debug Monitor",   0x30),
        new STM32InterruptVector("PendSV",          0x38),
        new STM32InterruptVector("SysTick",         0x3C),
        new STM32InterruptVector("WWDG",            0x40),
        new STM32InterruptVector("PVD",             0x44),
        new STM32InterruptVector("TAMP_STAMP",      0x48),
        new STM32InterruptVector("RTC_WKUP",        0x4C),
        new STM32InterruptVector("FLASH",           0x50),
        new STM32InterruptVector("RCC",             0x54),
        new STM32InterruptVector("EXTI0",           0x58),
        new STM32InterruptVector("EXTI1",           0x5C),
        new STM32InterruptVector("EXTI2",           0x60),
        new STM32InterruptVector("EXTI3",           0x64),
        new STM32InterruptVector("EXTI4",           0x68),
        new STM32InterruptVector("DMA1_Stream0",    0x6C),
        new STM32InterruptVector("DMA1_Stream1",    0x70),
        new STM32InterruptVector("DMA1_Stream2",    0x74),
        new STM32InterruptVector("DMA1_Stream3",    0x78),
        new STM32InterruptVector("DMA1_Stream4",    0x7C),
        new STM32InterruptVector("DMA1_Stream5",    0x80),
        new STM32InterruptVector("DMA1_Stream6",    0x84),
        new STM32InterruptVector("ADC",             0x88),
        new STM32InterruptVector("CAN1_TX",         0x8C),
        new STM32InterruptVector("CAN1_RX0",        0x90),
        new STM32InterruptVector("CAN1_RX1",        0x94),
        new STM32InterruptVector("CAN1_SCE",        0x98),
        new STM32InterruptVector("EXTI9_5",         0x9C),
        new STM32InterruptVector("TIM1_BRK_TIM9",   0xA0),
        new STM32InterruptVector("TIM1_UP_TIM10",   0xA4),
        new STM32InterruptVector("TIM1_TRG_COM_TIM11",0xA8),
        new STM32InterruptVector("TIM1_CC",         0xAC),
        new STM32InterruptVector("TIM2",            0xB0),
        new STM32InterruptVector("TIM3",            0xB4),
        new STM32InterruptVector("TIM4",            0xB8),
        new STM32InterruptVector("I2C1_EV",         0xBC),
        new STM32InterruptVector("I2C1_ER",         0xC0),
        new STM32InterruptVector("I2C2_EV",         0xC4),
        new STM32InterruptVector("I2C2_ER",         0xC8),
        new STM32InterruptVector("SPI1",            0xCC),
        new STM32InterruptVector("SPI2",            0xD0),
        new STM32InterruptVector("USART1",          0xD4),
        new STM32InterruptVector("USART2",          0xD8),
        new STM32InterruptVector("USART3",          0xDC),
        new STM32InterruptVector("EXTI15_10",       0xE0),
        new STM32InterruptVector("RTC_Alarm",       0xE4),
        new STM32InterruptVector("OTG_FS_WKUP",     0xE8),
    };

    private static class STM32MemRegion {
        String name;
        int addr;
        int size;
        boolean read;
        boolean write;
        boolean execute;
        private STM32MemRegion(String name, int addr, int size, boolean read, boolean write, boolean execute) {
            this.name = name;
            this.addr = addr;
            this.size = size;
            this.read = read;
            this.write = write;
            this.execute = execute;
        }
    }
    // Pull these regions from the datasheet
    private static final STM32MemRegion [] STM32MEM = {
        new STM32MemRegion("TIM2",              0x40000000, 0x400,  true,   true,   false),
        new STM32MemRegion("TIM3",              0x40000400, 0x400,  true,   true,   false),
        new STM32MemRegion("TIM4",              0x40000800, 0x400,  true,   true,   false),
        new STM32MemRegion("RTC",               0x40002800, 0x400,  true,   true,   false),
        new STM32MemRegion("WWDG",              0x40002C00, 0x400,  true,   true,   false),
        new STM32MemRegion("IWDG",              0x40003000, 0x400,  true,   true,   false),
        new STM32MemRegion("SPI2",              0x40003800, 0x400,  true,   true,   false),
        new STM32MemRegion("USART2",            0x40004400, 0x400,  true,   true,   false),
        new STM32MemRegion("USART3",            0x40004800, 0x400,  true,   true,   false),
        new STM32MemRegion("I2C1",              0x40005400, 0x400,  true,   true,   false),
        new STM32MemRegion("I2C2",              0x40005800, 0x400,  true,   true,   false),
        new STM32MemRegion("USB_REGS",          0x40005C00, 0x400,  true,   true,   false),
        new STM32MemRegion("USB_RAM",           0x40006000, 0x400,  true,   true,   false),
        new STM32MemRegion("CAN",               0x40006400, 0x400,  true,   true,   false),
        new STM32MemRegion("BKP",               0x40006C00, 0x400,  true,   true,   false),
        new STM32MemRegion("PWR",               0x40007000, 0x400,  true,   true,   false),
        new STM32MemRegion("AFIO",              0x40010000, 0x400,  true,   true,   false),
        new STM32MemRegion("EXTI",              0x40010400, 0x400,  true,   true,   false),
        new STM32MemRegion("GPIOA",             0x40010800, 0x400,  true,   true,   false),
        new STM32MemRegion("GPIOB",             0x40010C00, 0x400,  true,   true,   false),
        new STM32MemRegion("GPIOC",             0x40011000, 0x400,  true,   true,   false),
        new STM32MemRegion("GPIOD",             0x40011400, 0x400,  true,   true,   false),
        new STM32MemRegion("GPIOE",             0x40011800, 0x400,  true,   true,   false),
        new STM32MemRegion("ADC1",              0x40012400, 0x400,  true,   true,   false),
        new STM32MemRegion("ADC2",              0x40012800, 0x400,  true,   true,   false),
        new STM32MemRegion("TIM1",              0x40012C00, 0x400,  true,   true,   false),
        new STM32MemRegion("SPI1",              0x40013000, 0x400,  true,   true,   false),
        new STM32MemRegion("USART1",            0x40013800, 0x400,  true,   true,   false),
        new STM32MemRegion("DMA",               0x40020000, 0x400,  true,   true,   false),
        new STM32MemRegion("RCC",               0x40021000, 0x400,  true,   true,   false),

        // TODO: Add the ability to select and load these in from the loader...
        new STM32MemRegion("FLASH",             0x40022000, 0x400,  true,   true,   false),
        new STM32MemRegion("SRAM",              0x20000000, 0x2800, true,   true,   true),
        new STM32MemRegion("System Memory",     0x1FFFF000, 0x800,  true,   true,   true),
        new STM32MemRegion("Option Bytes",      0x1FFFF800, 0x10,   true,   false,  false),
    };
    @Override
    public String getName() {

        // TODO: Name the loader.  This name must match the name of the loader in the .opinion
        // files.
        return "STM32FEBKxx";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it
        // can load it, return the appropriate load specifications.

        // The STM32 has a 32 bit Arm Cortex LE core, so that is the language that we will use
        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        FlatProgramAPI api = new FlatProgramAPI(program,monitor);
        InputStream inStream = provider.getInputStream(0);
        Memory mem = program.getMemory();
        // TODO: Load the bytes from 'provider' into the 'program'.
        // This is where we actually "Load" the program into ghidra

        // First we loop through our memory map that we created:
        for(STM32MemRegion memregion: STM32MEM)    {
            try {
                MemoryBlock blk = mem.createUninitializedBlock(memregion.name, api.toAddr(memregion.addr), memregion.size, false);
                blk.setRead(memregion.read);
                blk.setWrite(memregion.write);
                blk.setExecute(memregion.execute);
                blk.setVolatile(true);
                api.createLabel(api.toAddr(memregion.addr),memregion.name.replace(" ","_"),false);
            } catch (LockException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (DuplicateNameException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (MemoryConflictException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (AddressOverflowException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        try {
            MemoryBlock blk = mem.createInitializedBlock("Main Memory", api.toAddr(0x8000000), inStream, 0x8000, monitor, false);
            blk.setRead(true);
            blk.setWrite(false);
            blk.setExecute(true);
        } catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            // Top of stack is first value in memory, see page 59 of datasheet
            // Make pointer, label it as stack start
            int stackAddr = mem.getInt(api.toAddr(0x8000000));
            Data stackAddrData = api.createDWord(api.toAddr(0x8000000));
            api.createLabel(api.toAddr(stackAddr),"bootloader_stack",true);
            api.createMemoryReference(stackAddrData, api.toAddr(stackAddr), ghidra.program.model.symbol.RefType.DATA);

            // Mark the entry point of the binary, also referenced in the datasheet on page 59

            /*
            int entryPoint = mem.getInt(api.toAddr(0x8000004));
            Data entryPointData = api.createDWord(api.toAddr(0x8000004));
            api.createDWord(api.toAddr(0x8000004));
            api.createLabel(api.toAddr(entryPoint),"_ENTRY_POINT",true);
            api.createMemoryReference(entryPointData, api.toAddr(entryPoint), ghidra.program.model.symbol.RefType.DATA);
            */
            for(STM32InterruptVector vector: STM32IVT) {
                int ptrVal = mem.getInt(api.toAddr(0x8000000+vector.addr));
                try {
                Data ptrData = api.createDWord(api.toAddr(0x8000000+vector.addr));
                api.createDWord(api.toAddr(0x8000000+vector.addr));
                api.createLabel(api.toAddr(0x8000000+vector.addr),vector.name,true);
                api.createMemoryReference(ptrData, api.toAddr(ptrVal), ghidra.program.model.symbol.RefType.DATA);
                } catch(ghidra.util.exception.InvalidInputException e) {
                    // This is ugly, need to fix
                    continue;
                }
            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
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
