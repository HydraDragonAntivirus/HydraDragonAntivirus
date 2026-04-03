#pragma once 
#include <ntddk.h>
#include <mmintrin.h>
#include <xmmintrin.h>
struct GuestContext
{
	DWORD64 Rax; DWORD64 Rbx;
	DWORD64 Rcx; DWORD64 Rdx;
	DWORD64 Rsi; DWORD64 Rdi;
	DWORD64 Rbp; DWORD64 R8;
	DWORD64 R9;	DWORD64 R10;
	DWORD64 R11; DWORD64 R12;
	DWORD64 R13; DWORD64 R14;
	DWORD64 R15;
};

DECLSPEC_ALIGN(16) struct SIMDGuestContext
{
	UINT16 FCW;
	UINT16 FSW;
	UINT16 FTW;
	UINT16 FOP;
	UINT32 IP;
	UINT16 CS;
	UINT16 Reserved0;
	UINT32 DP;
	UINT16 DS : 2;
	UINT16 Reserved1;
	UINT32 MXCSR;
	UINT32 Reserved2;
	__m64 st0;
	__m64 Reserved3;
	__m64 st1;
	__m64 Reserved4;
	__m64 st2;
	__m64 Reserved5;
	__m64 st3;
	__m64 Reserved6;
	__m64 st4;
	__m64 Reserved7;
	__m64 st5;
	__m64 Reserved8;
	__m64 st6;
	__m64 Reserved9;
	__m64 st7;
	__m64 Reserved10;
	__m128 Xmm0; 
	__m128 Xmm1;
	__m128 Xmm2;
	__m128 Xmm3;
	__m128 Xmm4;
	__m128 Xmm5;
	__m128 Xmm6;
	__m128 Xmm7;
	__m128 Xmm8;
	__m128 Xmm9;
	__m128 Xmm10;
	__m128 Xmm11;
	__m128 Xmm12;
	__m128 Xmm13;
	__m128 Xmm14;
	__m128 Xmm15;
};