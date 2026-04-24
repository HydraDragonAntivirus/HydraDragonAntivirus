#pragma once
#include <InitGuid.h>
#include <TinyAvCore.h>

class CMosPeScanModule :
	public CRefCount,
	public IScanModule
{
protected:
	MODULE_INFO m_info;
	IPeFile *m_parser;
	IMosSignatureEngine *m_sigEngine;
	virtual ~CMosPeScanModule();


public:
	CMosPeScanModule();

	DECLARE_REF_COUNT();

	virtual HRESULT WINAPI QueryInterface(__in REFIID riid, __out void **ppvObject);

	virtual HRESULT WINAPI GetModuleInfo(__out MODULE_INFO *scanInfo) override;
	virtual ModuleType WINAPI GetType(void) override;
	virtual HRESULT WINAPI GetName(__out BSTR *name) override;

	virtual HRESULT WINAPI OnScanInitialize(void) override;
	virtual HRESULT WINAPI Scan(__in IVirtualFs *file, __in IFsEnumContext *context, __in IScanObserver *observer) override;
	virtual HRESULT WINAPI OnScanShutdown(void) override;
};
