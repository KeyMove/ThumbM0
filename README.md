ARM Thumb 指令集编解码器

这个类实现了 ARM Thumb 指令集的编码和解码功能，支持16位 Thumb 指令的处理，
包括反汇编、汇编、地址计算和标签处理等功能。

## 功能特点
- 支持大多数 Thumb 指令的编码和解码
- 处理 PC 相对地址和标签
- 支持特殊寄存器(SP, LR, PC)
- 提供十六进制格式化工具
- 支持分支指令的标签修复

## 使用示例

### 1. 反汇编机器码
```javascript
const thumb = new ThumbM0();
const machineCode = new Uint8Array([0x01, 0x20, 0x02, 0x21, 0x08, 0x44]);
const disassembly = thumb.parseThumb(machineCode, true);
console.log(disassembly);
```

### 2. 汇编代码生成机器码
```javascript
const assemblyCode = `
    MOV R0, #1
    MOV R1, #2
    ADD R0, R0, R1
`;
const encoded = thumb.parseASM(assemblyCode);
console.log(encoded);
```

### 3. 编码单条指令
```javascript
const [opcode, mnemonic, operands] = thumb.encodeThumb('ADD R0, R1, R2');
console.log(`Opcode: 0x${thumb.Hex16(opcode)}, Mnemonic: ${mnemonic}, Operands: ${operands}`);
```

### 4. 十六进制格式化
```javascript
console.log(thumb.Hex8(15));    // 输出 "0F"
console.log(thumb.Hex16(255));  // 输出 "00FF"
console.log(thumb.Hex32(65535));// 输出 "0000FFFF"
```

## 方法概述
- `parseThumb()` - 反汇编机器码
- `parseASM()` - 汇编代码生成机器码
- `encodeThumb()` - 编码单条指令
- `Hex8/Hex16/Hex32()` - 十六进制格式化
- `bits()` - 位提取工具
- `decode()` - 机器码解码内部方法
