#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/mman.h>

using namespace std;

int global_size = 0x800;

class Vm{
private:
	void init_stack(unsigned int t,unsigned char* ret,unsigned long long old_rbp);

	unsigned char get_char(unsigned char **addr);
	unsigned short get_word(unsigned char **addr);
	unsigned int get_dword(unsigned char **addr);
	unsigned long long get_qword(unsigned char **addr);

	unsigned char get_magic(unsigned char **addr);
	unsigned char get_reg(unsigned char** addr);
	unsigned long long get_value(unsigned char magic,unsigned char **addr);
	void check_reg(unsigned char index);
	void check_stack();
	void error(string info);
	void split(unsigned char magic,unsigned long long *hi,unsigned long long *lo);

	unsigned long long rsp;
	unsigned long long rbp;
	unsigned int size;
	int used;
	unsigned long long regs[8];
	unsigned char *text_seg;
public:
	Vm(){
		//this->text_seg = (unsigned char*)mmap(0,0x1000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
		this->text_seg = new unsigned char[0x1000];
		this->init_stack(global_size,0,0);
	}  
	void read_cmd();
	unsigned int check_cmd();
	void run_cmd(unsigned int op_num);
	void set_sandbox();
};

void Vm::init_stack(unsigned int t,unsigned char* ret,unsigned long long old_rbp){
	this->rsp = (unsigned long long)new unsigned char[t];
	this->rbp = this->rsp + (unsigned long long)t;
	
	this->rbp -= 8;
	*(unsigned long long*)this->rbp = (unsigned long long)ret;
	this->rbp -= 8;
	*(unsigned long long*)this->rbp = old_rbp;
	this->rsp = this->rbp;

	this->size = (t - 0x10) / 8;
	this->used = 0;	
}

unsigned char Vm::get_char(unsigned char** addr){
	unsigned char* res = (unsigned char*)*addr;
	*addr = res + 1;
	return *res;
}
unsigned short Vm::get_word(unsigned char** addr){
	unsigned short* res = (unsigned short*)*addr;
	*addr = (unsigned char*)res + 2;
	return *res;
}
unsigned int Vm::get_dword(unsigned char** addr){
	unsigned int* res = (unsigned int*)*addr;
	*addr = (unsigned char*)res + 4;
	return *res;
}
unsigned long long Vm::get_qword(unsigned char** addr){
	unsigned long long* res = (unsigned long long*)*addr;
	*addr = (unsigned char*)res + 8;
	return *res;
}

unsigned char Vm::get_reg(unsigned char **addr){
	unsigned char res = get_char(addr);
	if (res >= 8)
		error("Regs out of range!");
	return res;
}

unsigned char Vm::get_magic(unsigned char **addr){
	unsigned char res = get_char(addr);
	if (res > 3 || res < 0)
		error("Magic number out of range!");
	return res;
}

unsigned long long Vm::get_value(unsigned char magic,unsigned char **addr){
	unsigned long long value = 0;
	switch(magic){
		case 0:
			value = (unsigned long long)get_char(addr) & 0xff;
			break;
		case 1:
			value = (unsigned long long)get_word(addr) & 0xffff;
			break;
		case 2:
			value = (unsigned long long)get_dword(addr) & 0xffffffff;
			break;
		case 3:
			value = get_qword(addr);
			break;											
		default:
			error("Invalid code!");
			break;
	}	
	return value;
}

void Vm::split(unsigned char magic,unsigned long long *hi,unsigned long long *lo){
	unsigned long long t = 0;
	for (int i = 0;i < (1 << magic);i++){
		t = t << 8;
		t += 0xff;
	}
	*lo = t;
	*hi = (~t);
}	

void Vm::check_stack(){
	if ((unsigned int)this->used > this->size || this->used < 0)
		error("Stack out of size!");
}

void Vm::error(string info){
	cout << info << endl;
	//printf(info.c_str());
	//puts("");
	exit(-1);
}

void Vm::read_cmd(){
	for(int i = 0;i < 0x1000;i++)
		read(0,(unsigned char*)this->text_seg + i,1);
}
unsigned int Vm::check_cmd(){
	unsigned char* text = this->text_seg;
	unsigned char opcode;
	unsigned char magic, reg_index, jmp_offset;
	unsigned char reg1, reg2;
	unsigned long long value;
	unsigned int op_num;
	unsigned int t,t_size;
	unsigned char* t_addr;
	unsigned long long ret[10];
	unsigned short call_offset;
	while(text < this->text_seg + 0x1000){
		opcode = get_char(&text);
		value = 0;
		op_num++;
		switch(opcode){
			case 1: // push reg
				reg_index = get_reg(&text);
				this->used++;
				check_stack();
				break;
			case 2: // pop reg
				reg_index = get_reg(&text);
				this->used--;
				check_stack();
				break;
			case 3: // add reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 4: // sub reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 5: // mul reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 6: // div reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 7: // and reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 8: // or reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 9: // xor reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			case 10: // neg reg
				reg_index = get_reg(&text);
				break;
			case 11: // jmp 
				jmp_offset = get_char(&text);
				if (text + jmp_offset - this->text_seg >= 0x1000)
					error(".text section out of range!");
				break;
			case 12: // call
				call_offset = get_word(&text);
				t_addr = text + call_offset;
				ret[(0x800-global_size) / 0x100] = (unsigned long long)text;
				if (t_addr < this->text_seg || t_addr >= this->text_seg + 0x1000)
					error(".text section out of range!");
				
				global_size -= 0x100;
				this->size -= (0x100 / 8);
				this->used = 0;
				text = t_addr;
				break;
			case 13: // ret
				global_size += 0x100;
				this->size += (0x100 / 8);
				this->used = 0;
				text = (unsigned char*)ret[(0x800-global_size) / 0x100];
				break;
			case 14: // mov reg reg
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				break;
			case 15: // mov [reg] reg
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				break;
			case 16: // mov reg [reg]
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				break;
			case 17: // mov reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				break;
			/*
			case 18:
				break;
			*/
			case 0xff:
				this->size = (0x800 - 0x10) / 8;
				this->used = 0;
				return op_num;
			default:
				error("Invalid code!");
				break;
		}
	}
	return op_num;
}

void Vm::run_cmd(unsigned int op_num){
	unsigned char* text = this->text_seg;
	unsigned char opcode;
	unsigned char magic, reg_index, jmp_offset;
	unsigned char reg1, reg2;
	unsigned long long value;
	unsigned long long hi,lo;
	unsigned int t,t_size;
	unsigned char* t_addr;
	unsigned short call_offset;
	while(op_num){
		opcode = get_char(&text);
		value = 0;
		op_num--;
		switch(opcode){
			case 1: // push reg
				reg_index = get_reg(&text);
				this->rsp -= 8;
				*(unsigned long long*)this->rsp = this->regs[reg_index];
				this->used++;
				//check_stack();
				break;
			case 2: // pop reg
				reg_index = get_reg(&text);
				this->regs[reg_index] = *(unsigned long long*)this->rsp;
				this->rsp += 8;
				this->used--;
				//check_stack();
				break;
			case 3: // add reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] + value));
				break;
			case 4: // sub reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] - value));
				break;
			case 5: // mul reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] * value));
				break;
			case 6: // div reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] / value));
				break;
			case 7: // and reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] & value));
				break;
			case 8: // or reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] | value));
				break;
			case 9: // xor reg value/reg
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & (lo&this->regs[reg_index] ^ value));
				break;
			case 10: // neg reg
				reg_index = get_reg(&text);
				this->regs[reg_index] = ~this->regs[reg_index];
				break;
			case 11: // jmp 
				jmp_offset = get_char(&text);
				if (text + jmp_offset - this->text_seg >= 0x1000)
					error(".text section out of range!");
				text += jmp_offset;
				break;
			case 12: // call
				call_offset = get_word(&text);
				t_addr = text + call_offset;
				if (t_addr < this->text_seg || t_addr >= this->text_seg + 0x1000)
					error(".text section out of range!");
				global_size -= 0x100;
				this->init_stack(global_size,text,this->rbp);
				text = t_addr;
				break;
			case 13: // ret
				text = (unsigned char*)*(unsigned long long*)(this->rbp + 8);
				this->rsp = this->rbp;
				this->rbp = *(unsigned long long*)this->rbp;
				delete [](unsigned char*)(this->rsp - this->size * 8);
				this->rsp = this->rbp;
				global_size += 0x100;
				this->size += (0x100 / 8);
				this->used = 0;
				break;
			case 14: // mov reg reg
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				this->regs[reg1] = this->regs[reg2];
				break;
			case 15: // mov [reg] reg
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				*(unsigned long long*)this->regs[reg1] = this->regs[reg2];
				break;
			case 16: // mov reg [reg]
				reg1 = get_reg(&text);
				reg2 = get_reg(&text);
				this->regs[reg1] = *(unsigned long long*)this->regs[reg2];
				break;
			case 17: // mov reg value
				magic = get_magic(&text);
				reg_index = get_reg(&text);
				value = get_value(magic,&text);
				split(magic,&hi,&lo);
				this->regs[reg_index] = (hi & this->regs[reg_index]) + (lo & value);
				break;
			/*
			case 18:
				for (int i = 0;i < 8; i++)
					printf("regs[%d] : %#llx\n",i,this->regs[i]);
				break;
			*/
			case 0xff:
				return;
			default:
				error("Invalid code!");
				break;
		}
	}
}
struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4), //前面两步用于检查arch
	BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,6),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),    //将帧的偏移0处，取4个字节数据，也就是系统调用号的值载入累加器
	BPF_JUMP(BPF_JMP+BPF_JGE,0x40000000,4,0), 
	BPF_JUMP(BPF_JMP+BPF_JEQ,0,4,0),    //当A == 59时，顺序执行下一条规则，否则跳过下一条规则，这里的59就是x64的execve系统调用
	BPF_JUMP(BPF_JMP+BPF_JEQ,2,3,0),
	BPF_JUMP(BPF_JMP+BPF_JEQ,60,2,0),
	BPF_JUMP(BPF_JMP+BPF_JEQ,231,1,0),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),     //返回KILL
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),    //返回ALLOW
};
struct sock_fprog prog = { 
	.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),    /* Number of filter blocks */
	.filter = filter, /* Pointer to array of BPF instructions */
};

void Vm::set_sandbox(){
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

int main(){
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
	
	Vm* vm = new Vm();
	//vm->set_sandbox();
	cout << "VM has been initialized. Please input your code: " << endl;
	vm->read_cmd();
	cout << "Now we will check your code and run it in a sandbox." << endl;
	unsigned int op_num = vm->check_cmd();
	global_size = 0x800;
	vm->set_sandbox();
	vm->run_cmd(op_num);
	return 0;
}