#pragma once
#include "pch.h"
#include <functional>
#include <fltuser.h>
//#incldue <string>
//#include "objects.h"
//#include "procmon.hpp"

namespace cmd {
namespace win {
	using Buffer = std::vector<uint8_t>;
	
	// Specialization for windows HANDLE
	struct HandleTraits
	{
		using ResourceType = HANDLE;
		static inline const ResourceType c_defVal = nullptr;
		static void cleanup(ResourceType& rsrc) noexcept;
	};
	using ScopedHandle = UniqueResource<HandleTraits>;

	struct HandlerContext 
	{
		const Byte* pInData;
		Size nInDataSize;
		Byte* pOutData = nullptr;
		Size nOutDataSize = 0;
		bool fHasResponce = false;
		std::pair<Size, Size> times;
	};
	using Handler = std::function<bool(HandlerContext& hctx)>;	

	class FltPortReceiver
	{
		/// Default size of receiving message (per thread).
		static const size_t c_nDefMsgSize = 0x1000;

		/// Maximal size of receiving message (per thread).
		static const size_t c_nMaxMsgSize = 0x100000; // 1Mb

		std::string		threadName;
		std::wstring	portName;
		Handler			handler;
		size_t			threadsCount;
		bool			fReplyMode;

		std::atomic_bool m_fTerminate = false;

		// Reconnect support: if the connection to the driver port is lost
		// (driver reload, service restart, ...) the receiving threads re-establish
		// it instead of dying. m_mtxReconnect serializes reconnect attempts and
		// m_nConnGeneration lets threads detect that the port was recreated.
		std::mutex m_mtxReconnect;
		std::atomic<size_t> m_nConnGeneration = 0;

		ScopedHandle m_pConnectionPort;
		std::vector<std::thread> m_pThreadPool;

		// Statistic
		std::mutex m_mtxStatistic;
		size_t m_nMsgCount = 0;
		double m_nMsgSize = 0;

		// Tread specific data
		struct OverlappedContext
		{
			// Must be first member of struct
			OVERLAPPED pOvlp = {};
			MemPtr<Byte> pData;
			size_t nDataSize = 0;
		};
		std::vector<OverlappedContext> m_pOvlpCtxes;
		ScopedHandle m_pCompletionPort;

		struct ReplyBuffer
		{
			FILTER_REPLY_HEADER header;
			byte buffer[c_nDefMsgSize];
			size_t size;
		};

		bool resizeMessage(OverlappedContext* pOvlpCtx);
		void pumpMessage(OverlappedContext* pOvlpCtx);
		void replyMessage(PFILTER_MESSAGE_HEADER pMessage, NTSTATUS nStatus);
		void replyDataMessage(PFILTER_MESSAGE_HEADER pMessage, ReplyBuffer& outMessage, NTSTATUS nStatus);
		bool reconnect(size_t nExpectedGen);
		
		void parseEventsThread();
		void parseEventsThreadInt();
	public:
		FltPortReceiver(const std::wstring& portName, size_t threadsCount, bool fReplyMode, const std::string& _threadName);
		void Start(Handler& handler);
		void Stop();

		// Number of attempts and delay to connect to the driver port.
		static const size_t c_nConnectAttempts = 10;
		static const DWORD c_nConnectBackoffMs = 1000;
		// Number of attempts and delay to re-establish a lost connection.
		static const size_t c_nReconnectAttempts = 5;
		static const DWORD c_nReconnectBackoffMs = 1000;
	};
}
}