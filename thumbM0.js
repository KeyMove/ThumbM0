    /**
     * ARM Thumb ָ��������
     * 
     * �����ʵ���� ARM Thumb ָ��ı���ͽ��빦�ܣ�֧��16λ Thumb ָ��Ĵ���
     * ��������ࡢ��ࡢ��ַ����ͱ�ǩ����ȹ��ܡ�
     * 
     * ## �����ص�
     * - ֧�ִ���� Thumb ָ��ı���ͽ���
     * - ���� PC ��Ե�ַ�ͱ�ǩ
     * - ֧������Ĵ���(SP, LR, PC)
     * - �ṩʮ�����Ƹ�ʽ������
     * - ֧�ַ�ָ֧��ı�ǩ�޸�
     * 
     * ## ʹ��ʾ��
     * 
     * ### 1. ����������
     * ```javascript
     * const thumb = new ThumbM0();
     * const machineCode = new Uint8Array([0x01, 0x20, 0x02, 0x21, 0x08, 0x44]);
     * const disassembly = thumb.parseThumb(machineCode, true);
     * console.log(disassembly);
     * ```
     * 
     * ### 2. ���������ɻ�����
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
     * ### 3. ���뵥��ָ��
     * ```javascript
     * const [opcode, mnemonic, operands] = thumb.encodeThumb('ADD R0, R1, R2');
     * console.log(`Opcode: 0x${thumb.Hex16(opcode)}, Mnemonic: ${mnemonic}, Operands: ${operands}`);
     * ```
     * 
     * ### 4. ʮ�����Ƹ�ʽ��
     * ```javascript
     * console.log(thumb.Hex8(15));    // ��� "0F"
     * console.log(thumb.Hex16(255));  // ��� "00FF"
     * console.log(thumb.Hex32(65535));// ��� "0000FFFF"
     * ```
     * 
     * ## ��������
     * - `parseThumb()` - ����������
     * - `parseASM()` - ���������ɻ�����
     * - `encodeThumb()` - ���뵥��ָ��
     * - `Hex8/Hex16/Hex32()` - ʮ�����Ƹ�ʽ��
     * - `bits()` - λ��ȡ����
     * - `decode()` - ����������ڲ�����
     * 
     * @class ThumbM0
     */
    class ThumbM0{
        constructor(){
            this.baseAddr=0x08000000;
            // �洢��ַ����ӳ���
            this.AddrName = {};
            // �洢ָ��������ӳ���
            this.thumbgenMap = {};
            // ��¼�����ĵ�ַ
            this.lastAddr = 0;
            // ָ��������ע�ắ��
            const genthumb=(name,req,action)=>{
                if(!this.thumbgenMap[name])this.thumbgenMap[name]={};
                if(this.thumbgenMap[name][req])console.log(`rep:${name}:${req}`);
                
                this.thumbgenMap[name][req]=action;
                return action;
            }
            // ����������������ת��Ϊָ��λ���Ķ������ַ���
            const b2=(x,b)=>`000000000000000${x.toString(2)}`.slice(-b);
            // �Ĵ�������ת������
            const Regs=(r)=>r<13 && (r<10 && `R${r} ` || `R${r}`) || (['SP','LR','PC'])[r-13];
            // ������ָ֧�����
            const Bcond=(b,offset)=>`B${(['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE'])[b]}  ${offset&0x80?(this.lastAddr=(((offset|~255)<<1)+4)):(this.lastAddr=((offset<<1)+4))}  ;@PC+BL`;
            // ���Ĵ���������¶Ϊ������
            this.Regs=Regs;
            // Thumb ָ������
            /* ָ���ʽ˵����
            '������ģʽ': {
                ��ģʽ: [
                    '����λģʽ',
                    ���뺯��,
                    ����������
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
         * ��ֵ����ȡָ��λģʽ�ĸ����ֶ�
         * @param {number} val - Ҫ��ȡ��ֵ
         * @param {string} bitformat - λģʽ�ַ���(��'ooosssddd')
         * @return {Array|null} ��ȡ���ֶ������null(��ƥ��ʱ)
         */
        bits(val, bitformat) {
            let lastchar = '';
            let v = 0;
            let vals = [];
            let arg = false;
            
            // ����λģʽ�ַ���
            for (let i = 0; i < bitformat.length; i++) {
                const c = bitformat[i];
                val <<= 1;
                
                // ���̶�λ
                if (c === '0' || c === '1') {
                    if (c === '0' && !(val & 0x10000)) continue;
                    if (c === '1' && (val & 0x10000)) continue;
                    return null; // ��ƥ��
                }
                
                // ����仯λ
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
            vals[0] = val & 0xffff; // ԭʼֵ
            return vals;
        }

        /**
         * ��Thumb���ָ�����Ϊ������
         * @param {string} code - ���ָ���ַ���
         * @return {Array|null} [������, ���Ƿ�, ������] �� null(��Чָ��ʱ)
         */
        encodeThumb(code) {
            // �����ǩ��ע��
            if (code.includes(':')) {
                code = code.split(':')[1];
            }
            
            // �������: ȥ��ע�͡��ո�ͳһ��Сд���Ƴ�����
            const cleanCode = code.split(';')[0].trim().toUpperCase().replaceAll('[', '').replaceAll(']', '');
            if (!cleanCode) return null; // ���л�ֻ��ע��
            
            // �ָ����Ƿ��Ͳ�����
            const parts = cleanCode.split(/\s+/);
            const mnemonic = parts[0];
            const args = parts.slice(1).join('');
            const operands = args.includes('{') ? 
                args.split('!').map(op => op.replace(',{', '{')) : 
                args.split(',').map(op => op.trim());
            
            // ����DCWαָ��
            if (mnemonic === 'DCW') {
                return [parseInt(operands[0], 16), 'DWC', [parseInt(operands[0], 16)]];
            }
            
            // ����ָ���(֧��ȫ�Ĵ���)
            const FULL_REG_INSTRUCTIONS = new Set(['MOV', 'CMP', 'ADD', 'SUB', 'BX', 'BLX']);
            const isFullRegInstruction = FULL_REG_INSTRUCTIONS.has(mnemonic);
            
            // ���ɲ�����ģʽ�ַ���������������
            let pattern = '';
            const parsedOperands = [];
            
            if (args.length > 0) {
                for (const op of operands) {
                    // �Ĵ�������
                    if (/^R([0-9]|1[0-5])$/.test(op)) {
                        let rs = parseInt(op.substring(1));
                        if (rs > 7) {
                            pattern = 'H' + pattern; // �߼Ĵ���
                        } else {
                            pattern = 'R' + pattern; // ��ͨ�Ĵ���
                        }
                        parsedOperands.unshift(rs);
                    } 
                    // ����Ĵ�������
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
                    // ����������
                    else if (op.startsWith('#')) {
                        pattern = 'O' + pattern;
                        parsedOperands.unshift(parseInt(op.substring(1)));
                    } 
                    // �Ĵ����б���
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
                    // ���ִ���
                    else if (parseInt(op) + Number.MAX_VALUE) {
                        pattern = 'O' + pattern;
                        parsedOperands.unshift(parseInt(op));
                    } 
                    // ��Ч����������
                    else {
                        parsedOperands.push(op);
                        return [null, mnemonic, parsedOperands];
                    }
                }
            }
            
            // ����ƥ���ָ��������
            if (!this.thumbgenMap[mnemonic] || !this.thumbgenMap[mnemonic][pattern]) {
                if (isFullRegInstruction) {
                    // ���Խ�����Ĵ���ת��Ϊ��ͨ�Ĵ���ģʽ
                    pattern = pattern.replaceAll('S', 'R').replaceAll('P', 'R')
                                .replaceAll('L', 'R').replaceAll('H', 'R');
                    if (!this.thumbgenMap[mnemonic] || !this.thumbgenMap[mnemonic][pattern]) {
                        throw new Error(`No matching instruction pattern for ${mnemonic} with operands ${pattern}`);
                    }
                } else {
                    throw new Error(`No matching instruction pattern for ${mnemonic} with operands ${pattern}`);
                }
            }
            
            // �������������������ؽ��
            return [this.thumbgenMap[mnemonic][pattern](...parsedOperands), mnemonic, parsedOperands];
        }
        
        /**
         * ���������벢���ɻ�����
         * @param {string} asm - �������ַ���
         * @param {boolean} advaddr - �Ƿ����ǩ�͵�ַ
         * @return {Array} ���ɵĻ������ֽ�����
         */
        parseASM(asm, advaddr = true) {
            let data = [];
            let asmline = asm.split('\n');
            
            // ��ַ�ͱ�ǩ����
            if (advaddr) {
                let addrmap = {};
                let bmap = [];
                let nullline = [];
                let addr = 0;
                const labeltype = new Set(['BIC', 'BKPT', 'BX', 'BLX']);
                
                // ��һ��ɨ��: �ռ���ǩ��ַ
                for (let i = 0; i < asmline.length; i++) {
                    const code = asmline[i];
                    if (code.includes(':')) {
                        addrmap[code.split(':')[0].trim()] = addr;
                    }
                    
                    const e = this.encodeThumb(code);
                    if (e != null) {
                        const v = e[0];
                        if (e[1] == 'BL') addr += 2; // BLָ��ռ4�ֽ�
                        if (e[1][0] == 'B') { // ��ָ֧��
                            if (!labeltype.has(e[1])) {
                                bmap.push([i, e[2][0], addr, code]);
                            }
                        }
                        addr += 2;
                    } else {
                        nullline.push(i);
                    }
                }
                
                // �滻��֧Ŀ��Ϊ������ƫ����
                for (let i = 0; i < bmap.length; i++) {
                    const e = bmap[i];
                    asmline[e[0]] = asmline[e[0]].replace(e[1], `${addrmap[e[1]] - e[2]}`);
                }
                
                // �Ƴ�����
                nullline.map(x => (asmline[x] = ''));
            }
            
            // ��������: д��16λֵ
            function w16(b) {
                data.push(b & 0xff);
                data.push((b >> 8) & 0xff);
            }
            
            // �ڶ���ɨ��: ���ɻ�����
            asmline.map(x => {
                let e = this.encodeThumb(x);
                if (e != null) {
                    const v = e[0];
                    if ((v & 0xf800) == 0xF800) w16(v >> 16); // 32λָ��ǰ�벿��
                    w16(v & 0xffff); // 16λָ���32λָ���벿��
                }
            });
            
            return data;
        }

        /**
         * �ݹ���������
         * @param {Object} tab - ָ���
         * @param {number} vals - ������ֵ
         * @param {number} org - ԭʼ��ַ
         * @return {string} �����Ļ��ָ��
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
                    
                    // ���ݲ����������ò�ͬ�Ľ��뺯��
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
         * ��Thumb�����뷴���Ϊ������
         * @param {Array|ArrayBuffer} bin - �������ֽ�����
         * @param {boolean} addrview - �Ƿ���ʾ��ַ
         * @param {boolean} jmpfix - �Ƿ��޸���ת��ǩ
         * @return {string} �������
         */
        parseThumb(bin, addrview = false, jmpfix = true) {
            let asm = [];
            let addr = 0;
            let base = this.baseAddr; // Ĭ�ϻ���ַ
            let dv = new DataView(new Uint8Array(bin).buffer);
            let count = bin.length;
            let dcw = []; // ��Ҫ��Ϊ���ݴ���ĵ�ַ
            let qjmp = new Set(); // ��תĿ���ַ
            
            const toHex32 = this.Hex32;
            
            // ����������
            while (count >= 2) {
                const code = dv.getUint16(addr, true);
                
                // ����������
                if (dcw.includes(addr)) {
                    asm.push(addrview ? 
                        `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  DCW  ${toHex32(code).substring(4)}` : 
                        `DCW  ${toHex32(code).substring(4)}`);
                    dcw.splice(dcw.indexOf(addr), 1);
                } 
                // ����ָ��
                else {
                    const asmv = this.decodeThumb(this.InstructionsCode, code);
                    const lastAddr = this.lastAddr;
                    
                    let asmv2 = addrview ? 
                        `:${toHex32(base + addr)} ${toHex32(code).substring(4)}  ${asmv}` : 
                        `${asmv}`;
                    
                    // ���������ַ����
                    if (asmv2.includes(';')) {
                        let vaddr;
                        switch (asmv2.split('@')[1]) {
                            case 'PC+ADDR': // PC��Ե�ַ����
                                vaddr = (addr + lastAddr + 4) & ~2;
                                dcw.push(vaddr);
                                dcw.push(vaddr + 2);
                                asmv2 = asmv2.replace('PC+ADDR', 
                                    `0x${toHex32(base + vaddr)}=0x${
                                        (vaddr + 4 <= bin.length) && toHex32(dv.getUint32(vaddr, true)) || '????????'
                                    }`);
                                break;
                                
                            case 'PC+BL': // ��֧����ָ��
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
                                
                            case 'PC+B': // ��ָ֧��
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
            
            // �����ת��ǩ
            if (jmpfix) {
                Array.from(qjmp).map(x => 
                    asm[x] = `Q${toHex32(base + (x << 1))}:${
                        (this.AddrName[base + (x << 1)] ? '     ;' + this.AddrName[base + (x << 1)] : '')
                    }\n` + asm[x]);
            }
            
            return asm.join('\n').replaceAll(';0\n', '');
        }

    }
