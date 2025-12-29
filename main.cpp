#include <iostream>
#include "addrenc.h"

uintptr_t AddressObfuscator::ks[KSCH_SZ] = { 0 };
uintptr_t AddressObfuscator::mk = 0;
bool AddressObfuscator::init = false;
DWORD AddressObfuscator::tls = 0;

int main() {
    int sd = 0xDEADBEEF;
    int* op = &sd;

    std::cout << "Original Address: 0x" << std::hex << reinterpret_cast<uintptr_t>(op) << std::endl;
    std::cout << "Original Value: 0x" << *op << std::endl;

    std::cout << "\n--- Static Obfuscation ---\n";
    auto obp = AddressObfuscator::obfs(op);
    std::cout << "Obfuscated: 0x" << reinterpret_cast<uintptr_t>(obp) << std::endl;

    auto dbp = AddressObfuscator::dobs(obp);
    std::cout << "Deobfuscated: 0x" << reinterpret_cast<uintptr_t>(dbp) << std::endl;
    std::cout << "Value: 0x" << *dbp << std::endl;

    std::cout << "\n--- Dynamic Obfuscation ---\n";
    for (int i = 0; i < 5; i++) {
        Sleep(1);
        auto ob = AddressObfuscator::obf(op);
        auto db = AddressObfuscator::dob(ob);
        std::cout << "R" << std::dec << i + 1 << " Obf: 0x" << std::hex << reinterpret_cast<uintptr_t>(ob);
        std::cout << " Deobf: 0x" << reinterpret_cast<uintptr_t>(db) << std::endl;
    }

    std::cout << "\n--- Secure Pointer ---\n";
    AddressObfuscator::SP<int> sp(&sd);
    std::cout << "SP Value: 0x" << *sp << std::endl;

    *sp = 0xCAFEBABE;
    std::cout << "Modified: 0x" << sd << std::endl;

    return 0;
}
