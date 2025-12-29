#ifndef ADDRENC_H
#define ADDRENC_H

#include <windows.h>
#include <random>
#include <intrin.h>

#define KSCH_SZ 8
#define RND_CNT 4

class AddressObfuscator {
private:
    static uintptr_t ks[KSCH_SZ];
    static uintptr_t mk;
    static bool init;
    static DWORD tls;

    static inline uintptr_t __fastcall gdk() {
        uintptr_t k = 0;
        k ^= __rdtsc();
        LARGE_INTEGER li;
        QueryPerformanceCounter(&li);
        k ^= li.QuadPart;
        k = (k * 0x5DEECE66D + 0xB) & ((1ULL << 48) - 1);
        return k;
    }

    static void __forceinline iks() {
        if (init) return;
        mk = __rdtsc() ^ GetCurrentProcessId();
        std::random_device rd;
        std::mt19937_64 g(rd() ^ mk);
        for (int i = 0; i < KSCH_SZ; i++) {
            ks[i] = g();
        }
        init = true;
        tls = TlsAlloc();
    }

    static __forceinline uintptr_t rol(uintptr_t v, int s) {
        s = s % 64;
        return (v << s) | (v >> (64 - s));
    }

    static __forceinline uintptr_t ror(uintptr_t v, int s) {
        s = s % 64;
        return (v >> s) | (v << (64 - s));
    }

    static uintptr_t __fastcall gtk() {
        iks();
        uintptr_t tk = reinterpret_cast<uintptr_t>(TlsGetValue(tls));
        if (tk == 0) {
            tk = gdk();
            TlsSetValue(tls, reinterpret_cast<LPVOID>(tk));
        }
        return tk;
    }

    template<int R>
    static __forceinline uintptr_t fst(uintptr_t d, uintptr_t rk) {
        uintptr_t l = (d >> 32) & 0xFFFFFFFF;
        uintptr_t r = d & 0xFFFFFFFF;
        uintptr_t t = r;
        r = l ^ ((r ^ rk) + rol(r, R % 32));
        l = t;
        return (l << 32) | r;
    }

    static uintptr_t __fastcall prm(uintptr_t v, uintptr_t k, bool enc) {
        if (enc) {
            v ^= k;
            for (int i = 0; i < RND_CNT; i++) {
                v = fst<7>(v, ks[i]);
                v = rol(v, (i * 11 + 13) % 64);
                v ^= ks[(i + RND_CNT) % KSCH_SZ];
            }
        }
        else {
            for (int i = RND_CNT - 1; i >= 0; i--) {
                v ^= ks[(i + RND_CNT) % KSCH_SZ];
                v = ror(v, (i * 11 + 13) % 64);
                v = fst<7>(v, ks[i]);
            }
            v ^= k;
        }
        return v;
    }

public:
    static uintptr_t __fastcall gok() {
        iks();
        return mk;
    }

    template<typename T>
    static T* __fastcall obf(T* p) {
        iks();
        uintptr_t a = reinterpret_cast<uintptr_t>(p);
        uintptr_t dk = gdk();
        uintptr_t o = prm(a, dk, true);
        return reinterpret_cast<T*>(o);
    }

    template<typename T>
    static T* __fastcall dob(T* op) {
        iks();
        uintptr_t o = reinterpret_cast<uintptr_t>(op);
        uintptr_t dk = gdk();
        uintptr_t a = prm(o, dk, false);
        return reinterpret_cast<T*>(a);
    }

    template<typename T>
    static T* __fastcall obfs(T* p) {
        iks();
        uintptr_t a = reinterpret_cast<uintptr_t>(p);
        uintptr_t o = a;

        o ^= ks[0];
        o = rol(o, 17);
        o ^= ks[1];
        o = ror(o, 23);
        o ^= ks[2];
        o = rol(o, 31);
        o ^= ks[3];
        o = ror(o, 11);
        o ^= ks[4];
        o = rol(o, 41);
        o ^= ks[5];
        o = ror(o, 19);
        o ^= ks[6];
        o = rol(o, 29);
        o ^= ks[7];

        return reinterpret_cast<T*>(o);
    }

    template<typename T>
    static T* __fastcall dobs(T* op) {
        iks();
        uintptr_t o = reinterpret_cast<uintptr_t>(op);

        o ^= ks[7];
        o = ror(o, 29);
        o ^= ks[6];
        o = rol(o, 19);
        o ^= ks[5];
        o = ror(o, 41);
        o ^= ks[4];
        o = rol(o, 11);
        o ^= ks[3];
        o = ror(o, 31);
        o ^= ks[2];
        o = rol(o, 23);
        o ^= ks[1];
        o = ror(o, 17);
        o ^= ks[0];

        return reinterpret_cast<T*>(o);
    }

    template<typename T>
    class SP {
    private:
        uintptr_t oa;

    public:
        SP(T* p = nullptr) {
            oa = reinterpret_cast<uintptr_t>(obfs(p));
        }

        T* __fastcall g() {
            T* t = reinterpret_cast<T*>(oa);
            return dobs(t);
        }

        void __fastcall s(T* p) {
            oa = reinterpret_cast<uintptr_t>(obfs(p));
        }

        T& operator*() {
            return *g();
        }

        T* operator->() {
            return g();
        }

        operator T* () {
            return g();
        }
    };
};

#endif
