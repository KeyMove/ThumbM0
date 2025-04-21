    /**
     * ARM Thumb 指令集编解码器
     * 
     * 这个类实现了 ARM Thumb 指令集的编码和解码功能，支持16位 Thumb 指令的处理，
     * 包括反汇编、汇编、地址计算和标签处理等功能。
     * 
     * ## 功能特点
     * - 支持大多数 Thumb 指令的编码和解码
     * - 处理 PC 相对地址和标签
     * - 支持特殊寄存器(SP, LR, PC)
     * - 提供十六进制格式化工具
     * - 支持分支指令的标签修复
     * 
     * ## 使用示例
     * 
     * ### 1. 反汇编机器码
     * ```javascript
     * const thumb = new ThumbM0();
     * const machineCode = new Uint8Array([0x01, 0x20, 0x02, 0x21, 0x08, 0x44]);
     * const disassembly = thumb.parseThumb(machineCode, true);
     * console.log(disassembly);
     * ```
     * 
     * ### 2. 汇编代码生成机器码
     * ```javascript
     * const assemblyCode = `
     *     MOV R0, #1
     *     MOV R1, #2
     *     ADD R0, R0, R1
     * `;
     * const encoded = thumb.parseASM(assemblyCode);
     * console.log(encoded);
     * ```
     * 
     * ### 3. 编码单条指令
     * ```javascript
     * const [opcode, mnemonic, operands] = thumb.encodeThumb('ADD R0, R1, R2');
     * console.log(`Opcode: 0x${thumb.Hex16(opcode)}, Mnemonic: ${mnemonic}, Operands: ${operands}`);
     * ```
     * 
     * ### 4. 十六进制格式化
     * ```javascript
     * console.log(thumb.Hex8(15));    // 输出 "0F"
     * console.log(thumb.Hex16(255));  // 输出 "00FF"
     * console.log(thumb.Hex32(65535));// 输出 "0000FFFF"
     * ```
     * 
     * ## 方法概述
     * - `parseThumb()` - 反汇编机器码
     * - `parseASM()` - 汇编代码生成机器码
     * - `encodeThumb()` - 编码单条指令
     * - `Hex8/Hex16/Hex32()` - 十六进制格式化
     * - `bits()` - 位提取工具
     * - `decode()` - 机器码解码内部方法
     * 
     * @class ThumbM0
     */
    class ThumbM0{
        constructor(){
            this.baseAddr=0x08000000;
            // 存储地址名称映射表
            this.AddrName = {};
            // 存储指令生成器映射表
            this.thumbgenMap = {};
            // 记录最后处理的地址
            this.lastAddr = 0;
            // 指令生成器注册函数
            const genthumb=(name,req,action)=>{
                if(!this.thumbgenMap[name])this.thumbgenMap[name]={};
                if(this.thumbgenMap[name][req])console.log(`rep:${name}:${req}`);
                
                this.thumbgenMap[name][req]=action;
                return action;
            }
            // 辅助函数：将数字转换为指定位数的二进制字符串
            const b2=(x,b)=>`000000000000000${x.toString(2)}`.slice(-b);
            // 寄存器名称转换函数
            const Regs=(r)=>r<13 && (r<10 && `R${r} ` || `R${r}`) || (['SP','LR','PC'])[r-13];
            // 条件分支指令处理函数
            const Bcond=(b,offset)=>`B${(['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE'])[b]}  ${offset&0x80?(this.lastAddr=(((offset|~255)<<1)+4)):(this.lastAddr=((offset<<1)+4))}  ;@PC+BL`;
            // 将寄存器函数暴露为类属性
            this.Regs=Regs;
            // Thumb 指令集编码表
            /* 指令格式说明：
            '二进制模式': {
                子模式: [
                    '参数位模式',
                    解码函数,
                    编码生成器
                ]
            }
            */
            this.InstructionsCode={
                '000mm':{
                    0:['ooooosssddd',(offset,Rs,Rd)=>`LSL  ${Regs(Rd)},${Regs(Rs)},#${offset}`,genthumb('LSL','ORR',(o,Rs,Rd)=>`0b00000${b2(o,5)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                    1:['ooooosssddd',(offset,Rs,Rd)=>`LSR  ${Regs(Rd)},${Regs(Rs)},#${offset}`,genthumb('LSR','ORR',(o,Rs,Rd)=>`0b00001${b2(o,5)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                    2:['ooooosssddd',(offset,Rs,Rd)=>`ASR  ${Regs(Rd)},${Regs(Rs)},#${offset}`,genthumb('ASR','ORR',(o,Rs,Rd)=>`0b00010${b2(o,5)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                    3:{
                        'mm':{
                            0:['nnnsssddd',(Rn,Rs,Rd)=>`ADD  ${Regs(Rd)},${Regs(Rs)},${Regs(Rn)}`,genthumb('ADD','RRR',(Rn,Rs,Rd)=>`0b0001100${b2(Rn,3)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            1:['nnnsssddd',(Rn,Rs,Rd)=>`SUB  ${Regs(Rd)},${Regs(Rs)},${Regs(Rn)}`,genthumb('SUB','RRR',(Rn,Rs,Rd)=>`0b0001101${b2(Rn,3)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            2:['ooosssddd',(Rn,Rs,Rd)=>`ADD  ${Regs(Rd)},${Regs(Rs)},#${Rn}`,genthumb('ADD','ORR',(o,Rs,Rd)=>`0b0001110${b2(o,3)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            3:['ooosssddd',(Rn,Rs,Rd)=>`SUB  ${Regs(Rd)},${Regs(Rs)},#${Rn}`,genthumb('SUB','ORR',(o,Rs,Rd)=>`0b0001111${b2(o,3)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                        }
                    },
                },
                '001mm':{
                    0:['dddoooooooo',(Rd,offset)=>`MOV  ${Regs(Rd)},#${offset}`,genthumb('MOV','OR',(o,Rd)=>`0b00100${b2(Rd,3)}${b2(o,8)}`|0)],
                    1:['dddoooooooo',(Rd,offset)=>`CMP  ${Regs(Rd)},#${offset}`,genthumb('CMP','OR',(o,Rd)=>`0b00101${b2(Rd,3)}${b2(o,8)}`|0)],
                    2:['dddoooooooo',(Rd,offset)=>`ADD  ${Regs(Rd)},#${offset}`,genthumb('ADD','OR',(o,Rd)=>`0b00110${b2(Rd,3)}${b2(o,8)}`|0)],
                    3:['dddoooooooo',(Rd,offset)=>`SUB  ${Regs(Rd)},#${offset}`,genthumb('SUB','OR',(o,Rd)=>`0b00111${b2(Rd,3)}${b2(o,8)}`|0)],
                },
                '0100mm':{
                    0:{
                        'mmmm':{
                            0: ['sssddd',(Rs,Rd)=>`AND  ${Regs(Rd)},${Regs(Rs)}`,genthumb('AND','RR',(Rs,Rd)=>`0b010000${b2( 0,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            1: ['sssddd',(Rs,Rd)=>`EOR  ${Regs(Rd)},${Regs(Rs)}`,genthumb('EOR','RR',(Rs,Rd)=>`0b010000${b2( 1,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            2: ['sssddd',(Rs,Rd)=>`LSL  ${Regs(Rd)},${Regs(Rs)}`,genthumb('LSL','RR',(Rs,Rd)=>`0b010000${b2( 2,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            3: ['sssddd',(Rs,Rd)=>`LSR  ${Regs(Rd)},${Regs(Rs)}`,genthumb('LSR','RR',(Rs,Rd)=>`0b010000${b2( 3,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            4: ['sssddd',(Rs,Rd)=>`ASR  ${Regs(Rd)},${Regs(Rs)}`,genthumb('ASR','RR',(Rs,Rd)=>`0b010000${b2( 4,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            5: ['sssddd',(Rs,Rd)=>`ADC  ${Regs(Rd)},${Regs(Rs)}`,genthumb('ADC','RR',(Rs,Rd)=>`0b010000${b2( 5,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            6: ['sssddd',(Rs,Rd)=>`SBC  ${Regs(Rd)},${Regs(Rs)}`,genthumb('SBC','RR',(Rs,Rd)=>`0b010000${b2( 6,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            7: ['sssddd',(Rs,Rd)=>`ROR  ${Regs(Rd)},${Regs(Rs)}`,genthumb('ROR','RR',(Rs,Rd)=>`0b010000${b2( 7,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            8: ['sssddd',(Rs,Rd)=>`TST  ${Regs(Rd)},${Regs(Rs)}`,genthumb('TST','RR',(Rs,Rd)=>`0b010000${b2( 8,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            9: ['sssddd',(Rs,Rd)=>`NEG  ${Regs(Rd)},${Regs(Rs)}`,genthumb('NEG','RR',(Rs,Rd)=>`0b010000${b2( 9,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            10:['sssddd',(Rs,Rd)=>`CMP  ${Regs(Rd)},${Regs(Rs)}`,genthumb('CMP','RR',(Rs,Rd)=>`0b010000${b2(10,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            11:['sssddd',(Rs,Rd)=>`CMN  ${Regs(Rd)},${Regs(Rs)}`,genthumb('CMN','RR',(Rs,Rd)=>`0b010000${b2(11,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            12:['sssddd',(Rs,Rd)=>`ORR  ${Regs(Rd)},${Regs(Rs)}`,genthumb('ORR','RR',(Rs,Rd)=>`0b010000${b2(12,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            13:['sssddd',(Rs,Rd)=>`MUL  ${Regs(Rd)},${Regs(Rs)}`,genthumb('MUL','RR',(Rs,Rd)=>`0b010000${b2(13,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            14:['sssddd',(Rs,Rd)=>`BIC  ${Regs(Rd)},${Regs(Rs)}`,genthumb('BIC','RR',(Rs,Rd)=>`0b010000${b2(14,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            15:['sssddd',(Rs,Rd)=>`MVN  ${Regs(Rd)},${Regs(Rs)}`,genthumb('MVN','RR',(Rs,Rd)=>`0b010000${b2(15,4)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                        }
                    },
                    1:{
                        'mm':{
                            0: ['hssssddd',(h,Rs,Rd)=>`ADD  ${Regs(Rd+h*8)},${Regs(Rs)}`,genthumb('ADD','RR',(Rs,Rd)=>`0b01000100${b2(((Rd&0x8)!=0)|0,1)}${b2(Rs,4)}${b2(Rd,3)}`|0)],
                            1: ['hssssddd',(h,Rs,Rd)=>`CMP  ${Regs(Rd+h*8)},${Regs(Rs)}`,genthumb('CMP','RR',(Rs,Rd)=>((Rd<8&&Rs<8)?(`0b010000${b2(10,4)}${b2(Rs,3)}${b2(Rd,3)}`):(`0b01000101${b2(((Rd&0x8)!=0)|0,1)}${b2(Rs,4)}${b2(Rd,3)}`))|0)],
                            2: ['hssssddd',(h,Rs,Rd)=>`MOV  ${Regs(Rd+h*8)},${Regs(Rs)}`,genthumb('MOV','RR',(Rs,Rd)=>`0b01000110${b2(((Rd&0x8)!=0)|0,1)}${b2(Rs,4)}${b2(Rd,3)}`|0)],
                            3: {
                                'm':{
                                    0:['ssssddd',(Rs,Rd)=>`BX    ${Regs(Rs)}`,genthumb('BX' ,'R',(Rs)=>`0b010001110${b2(Rs,4)}000`|0)],
                                    1:['ssssddd',(Rs,Rd)=>`BLX   ${Regs(Rs)}`,genthumb('BLX','R',(Rs)=>`0b010001111${b2(Rs,4)}000`|0)],
                                }
                            },
                        }
                    },
                    2:['ddoooooooo',(Rd,offset)=>`LDR  ${Regs(Rd)},[PC, #${(this.lastAddr=offset*4)}]  ;@PC+ADDR`,genthumb('LDR','OPR',(o,Rb,Rd)=>`0b01001${b2(Rd,3)}${b2(o>>2,8)}`|0)],
                    3:['ddoooooooo',(Rd,offset)=>`LDR  ${Regs(Rd+4)},[PC, #${(this.lastAddr=offset*4)}]  ;@PC+ADDR`],
                },
                '0101mmm':{
                    6:['ooobbbddd',(Ro,Rb,Rd)=>`LDRB ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('LDRB','RRR',(Ro,Rb,Rd)=>`0b0101${b2(6,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    4:['ooobbbddd',(Ro,Rb,Rd)=>`LDR  ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('LDR' ,'RRR',(Ro,Rb,Rd)=>`0b0101${b2(4,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    2:['ooobbbddd',(Ro,Rb,Rd)=>`STRB ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('STRB','RRR',(Ro,Rb,Rd)=>`0b0101${b2(2,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    0:['ooobbbddd',(Ro,Rb,Rd)=>`STR  ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('STR' ,'RRR',(Ro,Rb,Rd)=>`0b0101${b2(0,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    7:['ooobbbddd',(Ro,Rb,Rd)=>`LDSH ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('LDSH','RRR',(Ro,Rb,Rd)=>`0b0101${b2(7,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    3:['ooobbbddd',(Ro,Rb,Rd)=>`LDSB ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('LDSB','RRR',(Ro,Rb,Rd)=>`0b0101${b2(3,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    5:['ooobbbddd',(Ro,Rb,Rd)=>`LDRH ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('LDRH','RRR',(Ro,Rb,Rd)=>`0b0101${b2(5,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    1:['ooobbbddd',(Ro,Rb,Rd)=>`STRH ${Regs(Rd)},[${Regs(Rb)},${Regs(Ro)}]`,genthumb('STRH','RRR',(Ro,Rb,Rd)=>`0b0101${b2(1,3)}${b2(Ro,3)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                },
                '011mm':{
                    3:['ooooobbbddd',(offset,Rb,Rd)=>`LDRB ${Regs(Rd)},[${Regs(Rb)},#${offset}]`    ,genthumb('LDRB','ORR',(o,Rb,Rd)=>`0b011${b2(3,2)}${b2(o,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    1:['ooooobbbddd',(offset,Rb,Rd)=>`LDR  ${Regs(Rd)},[${Regs(Rb)},#${offset*4}]`  ,genthumb('LDR' ,'ORR',(o,Rb,Rd)=>`0b011${b2(1,2)}${b2(o>>2,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    0:['ooooobbbddd',(offset,Rb,Rd)=>`STR  ${Regs(Rd)},[${Regs(Rb)},#${offset*4}]`  ,genthumb('STR' ,'ORR',(o,Rb,Rd)=>`0b011${b2(0,2)}${b2(o>>2,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    2:['ooooobbbddd',(offset,Rb,Rd)=>`STRB ${Regs(Rd)},[${Regs(Rb)},#${offset}]`    ,genthumb('STRB','ORR',(o,Rb,Rd)=>`0b011${b2(2,2)}${b2(o,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                },
                '100mm':{
                    0:['ooooobbbddd',(offset,Rb,Rd)=>`STRH ${Regs(Rd)},[${Regs(Rb)},#${offset*2}]`,genthumb('STRH','ORR',(o,Rb,Rd)=>`0b100${b2(0,2)}${b2(o>>1,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    1:['ooooobbbddd',(offset,Rb,Rd)=>`LDRH ${Regs(Rd)},[${Regs(Rb)},#${offset*2}]`,genthumb('LDRH','ORR',(o,Rb,Rd)=>`0b100${b2(1,2)}${b2(o>>1,5)}${b2(Rb,3)}${b2(Rd,3)}`|0)],
                    2:['dddoooooooo',   (Rd,offset)=>`STR  ${Regs(Rd)},[SP,#${offset*4}]`         ,genthumb('STR','OSR',(o,Rb,Rd)=>`0b100${b2(2,2)}${b2(Rd,3)}${b2(o>>2,8)}`|0)],
                    3:['dddoooooooo',   (Rd,offset)=>`LDR  ${Regs(Rd)},[SP,#${offset*4}]`         ,genthumb('LDR','OSR',(o,Rb,Rd)=>`0b100${b2(3,2)}${b2(Rd,3)}${b2(o>>2,8)}`|0)],
                },
                '1010m':{
                    0:['dddoooooooo',(Rd,offset)=>`ADD  ${Regs(Rd)},[PC,#${offset*4}]`,genthumb('ADD','OPR',(o,Rb,Rd)=>`0b10100${b2(Rd,3)}${b2(o>>2,8)}`|0)],
                    1:['dddoooooooo',(Rd,offset)=>`ADD  ${Regs(Rd)},[SP,#${offset*4}]`,genthumb('ADD','OSR',(o,Rb,Rd)=>`0b10101${b2(Rd,3)}${b2(o>>2,8)}`|0)],
                },
                '1011mmmm':{
                    0:{
                        'm':{
                            0:['ooooooo',(offset)=>`ADD  SP,#${(offset*4)}`,genthumb('ADD','OS',(o,Rd)=>`0b1011${b2(0,4)}0${b2(o>>2,7)}`|0)],
                            1:['ooooooo',(offset)=>`SUB  SP,#${(offset*4)}`,genthumb('SUB','OS',(o,Rd)=>`0b1011${b2(0,4)}1${b2(o>>2,7)}`|0)],
                        }
                    },
                    2:{
                        'mm':{
                            0:['sssddd',(Rs,Rd)=>`SXTH ${Regs(Rd)}, ${Regs(Rs)}`,genthumb('SXTH','RR',(Rs,Rd)=>`0b1011${b2(2,4)}${b2(0,2)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            1:['sssddd',(Rs,Rd)=>`SXTB ${Regs(Rd)}, ${Regs(Rs)}`,genthumb('SXTB','RR',(Rs,Rd)=>`0b1011${b2(2,4)}${b2(1,2)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            2:['sssddd',(Rs,Rd)=>`UXTH ${Regs(Rd)}, ${Regs(Rs)}`,genthumb('UXTH','RR',(Rs,Rd)=>`0b1011${b2(2,4)}${b2(2,2)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                            3:['sssddd',(Rs,Rd)=>`UXTB ${Regs(Rd)}, ${Regs(Rs)}`,genthumb('UXTB','RR',(Rs,Rd)=>`0b1011${b2(2,4)}${b2(3,2)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                        }
                    },
                    4: ['rrrrrrrr',(r)=>`PUSH {${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}}`.replace(',}','}'),genthumb('PUSH','A',(Rlist)=>`0b1011010${b2(((Rlist&0x100)!=0)|0,1)}${b2(Rlist&0xff,8)}`|0)],
                    5: ['rrrrrrrr',(r)=>`PUSH {${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}LR}`],
                    10:{
                        'mm':{
                            0:['sssddd',(Rs,Rd)=>`REV  ${Regs(Rd)}, ${Regs(Rs)}`,genthumb('REV','RR',(Rs,Rd)=>`0b1011${b2(10,4)}${b2(0,2)}${b2(Rs,3)}${b2(Rd,3)}`|0)],
                        }
                    },
                    12: ['rrrrrrrr',(r)=>`POP  {${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}}`.replace(',}','}'),genthumb('POP','A',(Rlist)=>`0b1011110${b2(((Rlist&0x200)!=0)|0,1)}${b2(Rlist&0xff,8)}`|0)],
                    13: ['rrrrrrrr',(r)=>`POP  {${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}PC}`],
                    14: ['oooooooo',(o)=>`BKPT #${o}`,genthumb('BKPT','O',(o)=>`0b1011${b2(14,4)}${b2(o,8)}`|0)],
                    15: ['oooooooo',(o)=>((o==0x20)?`WFE`:(o==0x30)?`WFI`:`NOP`),genthumb('WFE','',(o)=>`0b1011${b2(15,4)}${b2(0x20,8)}`|0),genthumb('WFI','',(o)=>`0b1011${b2(15,4)}${b2(0x30,8)}`|0),genthumb('NOP','',(o)=>`0b1011${b2(15,4)}${b2(0,8)}`|0)],
                },
                '1100m':{
                    0:['bbboooooooo',(Rb,r)=>`STM  ${Regs(Rb)}!,{${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}}`.replace(',}','}'),genthumb('STM','AR',(Rlist,Rb)=>`0b11000${b2(Rb,3)}${b2(Rlist&0xff,8)}`|0)],
                    1:['bbboooooooo',(Rb,r)=>`LDM  ${Regs(Rb)}!,{${r&0x80 && 'R7,' || ''}${r&0x40 && 'R6,' || ''}${r&0x20 && 'R5,' || ''}${r&0x10 && 'R4,' || ''}${r&0x8 && 'R3,' || ''}${r&0x4 && 'R2,' || ''}${r&0x2 && 'R1,' || ''}${r&0x1 && 'R0,' || ''}}`.replace(',}','}'),genthumb('LDM','AR',(Rlist,Rb)=>`0b11001${b2(Rb,3)}${b2(Rlist&0xff,8)}`|0)],
                },
                '1101mmmm':{
                    0: ['oooooooo',(offset)=>Bcond(0,offset) ,genthumb('BEQ','O',(o)=>`0b1101${b2( 0,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    1: ['oooooooo',(offset)=>Bcond(1,offset) ,genthumb('BNE','O',(o)=>`0b1101${b2( 1,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    2: ['oooooooo',(offset)=>Bcond(2,offset) ,genthumb('BCS','O',(o)=>`0b1101${b2( 2,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    3: ['oooooooo',(offset)=>Bcond(3,offset) ,genthumb('BCC','O',(o)=>`0b1101${b2( 3,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    4: ['oooooooo',(offset)=>Bcond(4,offset) ,genthumb('BMI','O',(o)=>`0b1101${b2( 4,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    5: ['oooooooo',(offset)=>Bcond(5,offset) ,genthumb('BPL','O',(o)=>`0b1101${b2( 5,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    6: ['oooooooo',(offset)=>Bcond(6,offset) ,genthumb('BVS','O',(o)=>`0b1101${b2( 6,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    7: ['oooooooo',(offset)=>Bcond(7,offset) ,genthumb('BVC','O',(o)=>`0b1101${b2( 7,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    8: ['oooooooo',(offset)=>Bcond(8,offset) ,genthumb('BHI','O',(o)=>`0b1101${b2( 8,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    9: ['oooooooo',(offset)=>Bcond(9,offset) ,genthumb('BLS','O',(o)=>`0b1101${b2( 9,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    10:['oooooooo',(offset)=>Bcond(10,offset),genthumb('BGE','O',(o)=>`0b1101${b2(10,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    11:['oooooooo',(offset)=>Bcond(11,offset),genthumb('BLT','O',(o)=>`0b1101${b2(11,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    12:['oooooooo',(offset)=>Bcond(12,offset),genthumb('BGT','O',(o)=>`0b1101${b2(12,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    13:['oooooooo',(offset)=>Bcond(13,offset),genthumb('BLE','O',(o)=>`0b1101${b2(13,4)}${b2(((o>>1)-2)&0xff,8)}`|0)],
                    15:['oooooooo',(offset)=>`SWI  ${offset}`,genthumb('SWI','O',(o)=>`0b1101${b2(15,4)}${b2(o&0xff,8)}`|0)],
                },
                '1110m':{
                    0:['ooooooooooo',(offset)=>`B    ${offset&0x400?(this.lastAddr=(((offset|~0x7ff)<<1)+4)):(this.lastAddr=((offset<<1)+4))}  ;@PC+BL`,genthumb('B','O',(o)=>`0b11100${b2(((o>>1)-2)&0x7ff,11)}`|0)],
                },
                //'1111':['hooooooooooo',(h,offset)=>`${h && ('BL    '+(lastAddr&0x0400?((((offset<<1)+(lastAddr<<12))|-1^(1<<23)-1)+2):2+((offset<<1)+(lastAddr<<12)))) || (';'+(lastAddr=offset)) }`]
                '1111m':{
                    0:['ooooooooooo',(offset)=>`;${(this.lastAddr=offset)}`],
                    1:['ooooooooooo',(offset)=>'BL   '+(this.lastAddr&0x0400?(this.lastAddr=((((offset<<1)+(this.lastAddr<<12))|-1^(1<<23)-1)+2)):(this.lastAddr=(2+((offset<<1)+(this.lastAddr<<12)))))+'  ;@PC+BL',genthumb('BL','O',(o)=>`0b11110${b2((((o>>1)-1)>>11)&0x7ff,11)}11111${b2(((o>>1)-1)&0x7ff,11)}`|0)],
                }
                //['hooooooooooo',(h,offset)=>`${h && ('BL    '+(lastAddr&0x0400?((((offset<<1)+(lastAddr<<12))|-1^(1<<23)-1)+2):2+((offset<<1)+(lastAddr<<12)))) || (';'+(lastAddr=offset)) }`]
            }

        }

        Hex8(value) {
            return ('0' + (value&0xff).toString(16).toUpperCase()).slice(-2);
        }
        Hex16(value) {
            return ('000' + (value&0xffff).toString(16).toUpperCase()).slice(-4);
        }
        Hex32(value) {
            return ('0000000' + (value).toString(16).toUpperCase()).slice(-8);
        }
        

        /**
         * 从值中提取指定位模式的各个字段
         * @param {number} val - 要提取的值
         * @param {string} bitformat - 位模式字符串(如'ooosssddd')
         * @return {Array|null} 提取的字段数组或null(不匹配时)
         */
        bits(val, bitformat) {
            let lastchar = '';
            let v = 0;
            let vals = [];
            let arg = false;
            
            // 遍历位模式字符串
            for (let i = 0; i < bitformat.length; i++) {
                const c = bitformat[i];
                val <<= 1;
                
                // 检查固定位
                if (c === '0' || c === '1') {
                    if (c === '0' && !(val & 0x10000)) continue;
                    if (c === '1' && (val & 0x10000)) continue;
                    return null; // 不匹配
                }
                
                // 处理变化位
                if (c !== lastchar) {
                    vals.push(v);
                    lastchar = c;
                    v = 0;
                    arg = true;
                }
                v <<= 1;
                v |= (val & 0x10000) != 0;
            }
            
            if (arg) vals.push(v);
            vals[0] = val & 0xffff; // 原始值
            return vals;
        }

        /**
         * 将Thumb汇编指令编码为机器码
         * @param {string} code - 汇编指令字符串
         * @return {Array|null} [机器码, 助记符, 操作数] 或 null(无效指令时)
         */
        encodeThumb(code) {
            // 处理标签和注释
            if (code.includes(':')) {
                code = code.split(':')[1];
            }
            
            // 清理代码: 去除注释、空格、统一大小写、移除括号
            const cleanCode = code.split(';')[0].trim().toUpperCase().replaceAll('[', '').replaceAll(']', '');
            if (!cleanCode) return null; // 空行或只有注释
            
            // 分割助记符和操作数
            const parts = cleanCode.split(/\s+/);
            const mnemonic = parts[0];
            const args = parts.slice(1).join('');
            const operands = args.includes('{') ? 
                args.split('!').map(op => op.replace(',{', '{')) : 
                args.split(',').map(op => op.trim());
            
            // 处理DCW伪指令
            if (mnemonic === 'DCW') {
                return [parseInt(operands[0], 16), 'DWC', [parseInt(operands[0], 16)]];
            }
            
            // 特殊指令处理(支持全寄存器)
            const FULL_REG_INSTRUCTIONS = new Set(['MOV', 'CMP', 'ADD', 'SUB', 'BX', 'BLX']);
            const isFullRegInstruction = FULL_REG_INSTRUCTIONS.has(mnemonic);
            
            // 生成操作数模式字符串并解析操作数
            let pattern = '';
            const parsedOperands = [];
            
            if (args.length > 0) {
                for (const op of operands) {
                    // 寄存器处理
                    if (/^R([0-9]|1[0-5])$/.test(op)) {
                        let rs = parseInt(op.substring(1));
                        if (rs > 7) {
                            pattern = 'H' + pattern; // 高寄存器
                        } else {
                            pattern = 'R' + pattern; // 普通寄存器
                        }
                        parsedOperands.unshift(rs);
                    } 
                    // 特殊寄存器处理
                    else if (op === 'SP') {
                        pattern = 'S' + pattern;
                        parsedOperands.unshift(13);
                    } else if (op === 'LR') {
                        pattern = 'L' + pattern;
                        parsedOperands.unshift(14);
                    } else if (op === 'PC') {
                        pattern = 'P' + pattern;
                        parsedOperands.unshift(15);
                    } 
                    // 立即数处理
                    else if (op.startsWith('#')) {
                        pattern = 'O' + pattern;
                        parsedOperands.unshift(parseInt(op.substring(1)));
                    } 
                    // 寄存器列表处理
                    else if (op.startsWith('{') && op.endsWith('}')) {
                        pattern = 'A' + pattern;
                        const regs = op.slice(1, -1).split(',');
                        let mask = 0;
                        for (const r of regs) {
                            const reg = r.trim();
                            if (reg === 'LR') mask |= 0x100;
                            else if (reg === 'PC') mask |= 0x200;
                            else if (reg.startsWith('R')) {
                                const num = parseInt(reg.substring(1));
                                mask |= (1 << num);
                            }
                        }
                        parsedOperands.unshift(mask);
                    } 
                    // 数字处理
                    else if (parseInt(op) + Number.MAX_VALUE) {
                        pattern = 'O' + pattern;
                        parsedOperands.unshift(parseInt(op));
                    } 
                    // 无效操作数处理
                    else {
                        parsedOperands.push(op);
                        return [null, mnemonic, parsedOperands];
                    }
                }
            }
            
            // 查找匹配的指令生成器
            if (!this.thumbgenMap[mnemonic] || !this.thumbgenMap[mnemonic][pattern]) {
                if (isFullRegInstruction) {
                    // 尝试将特殊寄存器转换为普通寄存器模式
                    pattern = pattern.replaceAll('S', 'R').replaceAll('P', 'R')
                                .replaceAll('L', 'R').replaceAll('H', 'R');
                    if (!this.thumbgenMap[mnemonic] || !this.thumbgenMap[mnemonic][pattern]) {
                        throw new Error(`No matching instruction pattern for ${mnemonic} with operands ${pattern}`);
                    }
                } else {
                    throw new Error(`No matching instruction pattern for ${mnemonic} with operands ${pattern}`);
                }
            }
            
            // 调用生成器函数并返回结果
            return [this.thumbgenMap[mnemonic][pattern](...parsedOperands), mnemonic, parsedOperands];
        }
        
        /**
         * 解析汇编代码并生成机器码
         * @param {string} asm - 汇编代码字符串
         * @param {boolean} advaddr - 是否处理标签和地址
         * @return {Array} 生成的机器码字节数组
         */
        parseASM(asm, advaddr = true) {
            let data = [];
            let asmline = asm.split('\n');
            
            // 地址和标签处理
            if (advaddr) {
                let addrmap = {};
                let bmap = [];
                let nullline = [];
                let addr = 0;
                const labeltype = new Set(['BIC', 'BKPT', 'BX', 'BLX']);
                
                // 第一遍扫描: 收集标签地址
                for (let i = 0; i < asmline.length; i++) {
                    const code = asmline[i];
                    if (code.includes(':')) {
                        addrmap[code.split(':')[0].trim()] = addr;
                    }
                    
                    const e = this.encodeThumb(code);
                    if (e != null) {
                        const v = e[0];
                        if (e[1] == 'BL') addr += 2; // BL指令占4字节
                        if (e[1][0] == 'B') { // 分支指令
                            if (!labeltype.has(e[1])) {
                                bmap.push([i, e[2][0], addr, code]);
                            }
                        }
                        addr += 2;
                    } else {
                        nullline.push(i);
                    }
                }
                
                // 替换分支目标为计算后的偏移量
                for (let i = 0; i < bmap.length; i++) {
                    const e = bmap[i];
                    asmline[e[0]] = asmline[e[0]].replace(e[1], `${addrmap[e[1]] - e[2]}`);
                }
                
                // 移除空行
                nullline.map(x => (asmline[x] = ''));
            }
            
            // 辅助函数: 写入16位值
            function w16(b) {
                data.push(b & 0xff);
                data.push((b >> 8) & 0xff);
            }
            
            // 第二遍扫描: 生成机器码
            asmline.map(x => {
                let e = this.encodeThumb(x);
                if (e != null) {
                    const v = e[0];
                    if ((v & 0xf800) == 0xF800) w16(v >> 16); // 32位指令前半部分
                    w16(v & 0xffff); // 16位指令或32位指令后半部分
                }
            });
            
            return data;
        }

        /**
         * 递归解码机器码
         * @param {Object} tab - 指令表
         * @param {number} vals - 机器码值
         * @param {number} org - 原始地址
         * @return {string} 解码后的汇编指令
         */
        decodeThumb(tab, vals, org = 0) {
            if (tab == null) {
                return `DCW  ${this.Hex16(org)}  ;not found`;
            }
            
            const keys = Object.keys(tab);
            for (let i = 0; i < keys.length; i++) {
                const key = keys[i];
                let v = this.bits(vals, key);
                if (!v) continue;
                
                let next = tab[key][v[1]];
                if (Array.isArray(next)) {
                    v = this.bits(v[0], next[0]);
                    const call = next[1];
                    
                    // 根据参数数量调用不同的解码函数
                    switch (v.length) {
                        case 2: return call(v[1]);
                        case 3: return call(v[1], v[2]);
                        case 4: return call(v[1], v[2], v[3]);
                    }
                    return null;
                } else {
                    return this.decodeThumb(next, v[0], vals);
                }
            }
        }

        /**
         * 将Thumb机器码反汇编为汇编代码
         * @param {Array|ArrayBuffer} bin - 机器码字节数组
         * @param {boolean} addrview - 是否显示地址
         * @param {boolean} jmpfix - 是否修复跳转标签
         * @return {string} 反汇编结果
         */
        parseThumb(bin, addrview = false, jmpfix = true) {
            let asm = [];
            let addr = 0;
            let base = this.baseAddr; // 默认基地址
            let dv = new DataView(new Uint8Array(bin).buffer);
            let count = bin.length;
            let dcw = []; // 需要作为数据处理的地址
            let qjmp = new Set(); // 跳转目标地址
            
            const toHex32 = this.Hex32;
            
            // 遍历机器码
            while (count >= 2) {
                const code = dv.getUint16(addr, true);
                
                // 处理数据字
                if (dcw.includes(addr)) {
                    asm.push(addrview ? 
                        `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  DCW  ${toHex32(code).substring(4)}` : 
                        `DCW  ${toHex32(code).substring(4)}`);
                    dcw.splice(dcw.indexOf(addr), 1);
                } 
                // 处理指令
                else {
                    const asmv = this.decodeThumb(this.InstructionsCode, code);
                    const lastAddr = this.lastAddr;
                    
                    let asmv2 = addrview ? 
                        `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  ${asmv}` : 
                        `${asmv}`;
                    
                    // 处理特殊地址引用
                    if (asmv2.includes(';')) {
                        let vaddr;
                        switch (asmv2.split('@')[1]) {
                            case 'PC+ADDR': // PC相对地址加载
                                vaddr = (addr + lastAddr + 4) & ~2;
                                dcw.push(vaddr);
                                dcw.push(vaddr + 2);
                                asmv2 = asmv2.replace('PC+ADDR', 
                                    `0x${toHex32(base + vaddr)}=0x${
                                        (vaddr + 4 <= bin.length) && toHex32(dv.getUint32(vaddr, true)) || '????????'
                                    }`);
                                break;
                                
                            case 'PC+BL': // 分支链接指令
                                if (jmpfix) {
                                    if ((addr + lastAddr) >= 0 && (addr + lastAddr) < bin.length) {
                                        asmv2 = `${asmv2.split(' ')[0]} Q${toHex32(base + addr + lastAddr)}  ;${
                                            asmv2.split(';')[0].trim()
                                        }->0x${toHex32(base + addr + lastAddr)} ${
                                            this.AddrName[base + addr + lastAddr] || ''
                                        }`;
                                        qjmp.add((addr + lastAddr) >> 1);
                                    } else {
                                        asmv2 = addrview ? 
                                            `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  DCW  ${toHex32(code).substring(4)}` : 
                                            `DCW  ${toHex32(code).substring(4)}`;
                                    }
                                } else {
                                    asmv2 = asmv2.replace('PC+BL', `0x${toHex32(base + addr + lastAddr)}`);
                                }
                                break;
                                
                            case 'PC+B': // 分支指令
                                if (jmpfix) {
                                    if ((addr + lastAddr) >= 0 && (addr + lastAddr) < bin.length) {
                                        asmv2 = `${asmv2.split(' ')[0]} Q${toHex32(base + addr + lastAddr)}  ;${
                                            asmv2.split(';')[0].trim()
                                        }->0x${toHex32(base + addr + lastAddr)} ${
                                            this.AddrName[base + addr + lastAddr] || ''
                                        }`;
                                        qjmp.add((addr + lastAddr) >> 1);
                                    } else {
                                        asmv2 = addrview ? 
                                            `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  DCW  ${toHex32(code).substring(4)}` : 
                                            `DCW  ${toHex32(code).substring(4)}`;
                                    }
                                } else {
                                    asmv2 = asmv2.replace('PC+B', `0x${toHex32(base + addr + lastAddr)}`);
                                }
                                break;
                        }
                    }
                    asm.push(asmv2);
                }
                
                addr += 2;
                count -= 2;
            }
            
            // 添加跳转标签
            if (jmpfix) {
                Array.from(qjmp).map(x => 
                    asm[x] = `Q${toHex32(base + (x << 1))}:${
                        (this.AddrName[base + (x << 1)] ? '     ;' + this.AddrName[base + (x << 1)] : '')
                    }\n` + asm[x]);
            }
            
            return asm.join('\n').replaceAll(';0\n', '');
        }

    }
