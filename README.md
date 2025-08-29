# ghidra-stm32feb

This is a loader for the STM32FEB series of microcontrollers found in eBikes.

## What it does

* Labels memory regions
* Labels IVT and entry point (assuming normal boot mode)

## Installation

You can install the loader via a zip on the releases page, or build the module yourself following instructions from the blog post

## Building with eclipse

After configuring Eclipse with the GhidraDev extension, this project can be built in Eclipse

## Building with gradle

You just need Java, gradle (https://gradle.org/releases/) and ghidra for building. Position in source dir and issue gradle command:

```
gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_11.4.1_PUBLIC
```

You can check what tasks you can also call with gradle with standard tasks options:

```
gradle tasks -PGHIDRA_INSTALL_DIR=/opt/ghidra_11.4.1_PUBLIC
```

Note: you can also put path to the ghidra in gradle.properties file:
```
GHIDRA_INSTALL_DIR=/opt/ghidra_11.4.1_PUBLIC
```

