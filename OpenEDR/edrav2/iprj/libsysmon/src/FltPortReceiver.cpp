#include "pch.h"
#include "FltPortReceiver.h"

namespace cmd {
namespace win {

		//
		//
		//
		void HandleTraits::cleanup(ResourceType& rsrc) noexcept
		{
			if (!::CloseHandle(rsrc))
				error::win::WinApiError(SL, "Can't close handle").log();
		}

		//
		//FltReceiverPort::FltReceiverPort
		//

		FltPortReceiver::FltPortReceiver(const std::wstring& _portName, size_t _threadsCount, bool _fReplyMode, const std::string& _threadName)
			: portName(_portName)
			, threadsCount(_threadsCount)
			, fReplyMode(_fReplyMode)
			, threadName(_threadName)
		{
		}

		bool FltPortReceiver::resizeMessage(OverlappedContext* pOvlpCtx)
		{
			DWORD nDataSize = 0;
			DWORD err = ERROR_SUCCESS;
			if (!::GetOverlappedResult(m_pCompletionPort, LPOVERLAPPED(pOvlpCtx), &nDataSize, TRUE))
				err = GetLastError();
			if (err != ERROR_INSUFFICIENT_BUFFER)
			{
				error::win::WinApiError(SL, err, "Fail to get overlapped result").log();
				return false;
			}

			if (nDataSize < pOvlpCtx->nDataSize || nDataSize > c_nMaxMsgSize)
			{
				LOGWRN("Overlapped data is too large <" << nDataSize << ">");
				return false;
			}

			pOvlpCtx->nDataSize = nDataSize;
			pOvlpCtx->pData = reallocMem(pOvlpCtx->pData, pOvlpCtx->nDataSize);
			if (pOvlpCtx->pData == nullptr)
				error::BadAlloc(SL, "Can't allocate memory for driver port message").throwException();
			LOGLVL(Trace, "Message resized to <" << nDataSize << "> bytes");

			return true;			
		}

		void FltPortReceiver::pumpMessage(OverlappedContext* pOvlpCtx)
		{
			ZeroMemory(&pOvlpCtx->pOvlp, sizeof(OVERLAPPED));
			// Pump messages into queue of completion port.
			HRESULT hr = ::FilterGetMessage(m_pConnectionPort,
				PFILTER_MESSAGE_HEADER(pOvlpCtx->pData.get()), DWORD(pOvlpCtx->nDataSize), &pOvlpCtx->pOvlp);
			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
				error::win::WinApiError(SL, hr, "FilterGetMessage failed").throwException();
		}

		void FltPortReceiver::replyMessage(PFILTER_MESSAGE_HEADER pMessage, NTSTATUS nStatus)
		{
			if (fReplyMode)
			{
				//  Reply the worker thread status to the filter
				//  This is important because the filter will also wait for the thread 
				//  in case that the thread is killed before telling filter 
				//  the parse is done or aborted.
				FILTER_REPLY_HEADER replyMsg = {};
				replyMsg.Status = nStatus;
				replyMsg.MessageId = pMessage->MessageId;
				HRESULT hr = ::FilterReplyMessage(m_pConnectionPort, &replyMsg, sizeof(replyMsg));
				if (FAILED(hr))
				{
					if (hr != ERROR_FLT_NO_WAITER_FOR_REPLY) // Driver exit with timeout
						error::win::WinApiError(SL, hr, "Failed to reply to the driver").throwException();
				}
			}
			else
				return;
		}

		void FltPortReceiver::replyDataMessage(PFILTER_MESSAGE_HEADER pMessage, ReplyBuffer& replyMessage, NTSTATUS nStatus)
		{
			if (!fReplyMode)
				return;

			replyMessage.header.MessageId = pMessage->MessageId;
			replyMessage.header.Status = nStatus;
			HRESULT hr = ::FilterReplyMessage(m_pConnectionPort, (FILTER_REPLY_HEADER*)&replyMessage, (DWORD)replyMessage.size);
			if (FAILED(hr))
			{
				if (hr != ERROR_FLT_NO_WAITER_FOR_REPLY) // Driver exit with timeout
					error::win::WinApiError(SL, hr, "Failed to reply to the driver").throwException();
			}
		}

		void FltPortReceiver::parseEventsThread()
		{
			// TODO: add thread guard here
			CMD_TRY
			{
				if (!::SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST))
					error::win::WinApiError(SL, "Can't set thread priority").log();
				sys::setThreadName(threadName);
				parseEventsThreadInt();
			}
			CMD_PREPARE_CATCH
			catch (error::Exception& e)
			{
				e.log(SL, threadName + " fail to parse event");
			}
			catch (...)
			{
				error::RuntimeError(SL, "Unknown error").log();
			}
		}

		void FltPortReceiver::parseEventsThreadInt()
		{
			LOGLVL(Detailed, "Event's receiving thread is started");

			while (!m_fTerminate)
			{
#ifdef ENABLE_EVENT_TIMINGS
				using namespace std::chrono;
				auto t0 = steady_clock::now();
#endif		
				//  Get overlapped structure asynchronously, the overlapped structure 
				//  was previously pumped by FilterGetMessage(...)
				DWORD nOutSize = 0;
				ULONG_PTR key = {};
				LPOVERLAPPED pOvlp = nullptr;

				// Remember the connection generation so a reconnect performed while
				// this message is being processed can be detected (it re-pumps all
				// contexts, so we must not re-pump the same context twice).
				const size_t nGenAtWait = m_nConnGeneration.load();

				if (!::GetQueuedCompletionStatus(m_pCompletionPort, &nOutSize, &key, &pOvlp, INFINITE))
				{
					//  The completion port handle associated with it is closed 
					//  while the call is outstanding, the function returns FALSE, 
					//  *lpOverlapped will be NULL, and GetLastError will return ERROR_ABANDONED_WAIT_0
					auto ec = GetLastError();
					if (HRESULT_FROM_WIN32(ec) == E_HANDLE || // Completion port becomes unavailable
						ec == ERROR_ABANDONED_WAIT_0 ||	// Completion port was closed
						ec == ERROR_OPERATION_ABORTED) // Rised when CancelIoEx() called
					{
						//  The connection to the driver port is lost (e.g. driver was
						//  reloaded). Re-establish it instead of terminating the thread.
						LOGWRN("Fltport connection is lost, reconnecting...");
						const size_t nGenOnDeath = m_nConnGeneration.load();
						while (!m_fTerminate && !reconnect(nGenOnDeath))
							::Sleep(500);
						continue;
					}

					if (ec != ERROR_INSUFFICIENT_BUFFER)
						error::win::WinApiError(SL, ec, "Can't receive driver message").throwException();

					LOGLVL(Trace, "Message buffer too small. Try to resize.");
					auto pOvlpCtx = (OverlappedContext*)pOvlp;
					if (!resizeMessage(pOvlpCtx))
					{
						auto pMessage = PFILTER_MESSAGE_HEADER(pOvlpCtx->pData.get());
						replyMessage(pMessage, S_FALSE);
					}

					pumpMessage(pOvlpCtx);
					continue;
				}
#ifdef ENABLE_EVENT_TIMINGS
				auto t1 = steady_clock::now();
#endif

				//  Recover message structure from overlapped structure.
				auto pMessage = PFILTER_MESSAGE_HEADER(((OverlappedContext*)pOvlp)->pData.get());
				Byte* pData = (Byte*)pMessage + sizeof(FILTER_MESSAGE_HEADER);
				Size nDataSize = nOutSize;

				// Collect statistics
				{
					std::scoped_lock lock(m_mtxStatistic);
					m_nMsgCount++;
					m_nMsgSize = nDataSize / m_nMsgCount + (m_nMsgCount - 1) * m_nMsgSize / m_nMsgCount;
				}

				ReplyBuffer reply;
				reply.size = sizeof(reply);
				bool result = false;

#ifdef ENABLE_EVENT_TIMINGS
				std::pair<Size, Size> times;
				HandlerContext hctx{ pData, nDataSize, reply.buffer, sizeof(reply.buffer), times };
				result = handler(hctx);
				auto t2 = steady_clock::now();
#else			
				HandlerContext hctx{ pData, nDataSize, reply.buffer, sizeof(reply.buffer) };
				result = handler(hctx);
#endif
				if(hctx.fHasResponce)
					replyDataMessage(pMessage, reply, (result) ? S_OK : S_FALSE);
				else
					replyMessage(pMessage, (result) ? S_OK : S_FALSE);

				//  If finalized flag is set from main thread, then it would break the while loop.
				if (m_fTerminate)
					break;

				// After we process the message, pump an overlapped structure into completion port again.
				// Skip re-pumping if the connection was re-established while this message was being
				// processed (the reconnecting thread already re-pumped every context).
				if (m_nConnGeneration.load() == nGenAtWait)
				{
					CMD_TRY
					{
						pumpMessage((OverlappedContext*)pOvlp);
					}
					CMD_PREPARE_CATCH
					catch (error::Exception& e)
					{
						// The connection may have died while processing; re-establish it.
						e.log(SL, threadName + " fail to re-pump message, reconnecting");
						const size_t nGen = m_nConnGeneration.load();
						while (!m_fTerminate && !reconnect(nGen))
							::Sleep(500);
					}
				}
#ifdef ENABLE_EVENT_TIMINGS
				auto t3 = steady_clock::now();
				milliseconds totalTime(duration_cast<milliseconds>(t3 - t0));
				milliseconds receiveTime(duration_cast<milliseconds>(t1 - t0));
				milliseconds parseTime(duration_cast<milliseconds>(t2 - t1));
				milliseconds pumpTime(duration_cast<milliseconds>(t3 - t2));
				LOGLVL(Debug, "Message statistic: total <" << totalTime.count() <<
					">, receive <" << receiveTime.count() << ">, parse <" << parseTime.count() <<
					"> [lbvs <" << times.first << ">, queue <" << times.second << ">], pump <" <<
					pumpTime.count() << ">, msg size <" << nDataSize << ">");
#endif
			}

			LOGLVL(Detailed, "Event's receiving thread is finished");
		}

		//
		//FltReceiverPort::Start
		//

		void FltPortReceiver::Start(Handler& _handler)
		{
			m_nMsgCount = 0;
			m_nMsgSize = 0;
			m_fTerminate = false;

			// Prepare the communication port.
			// The driver port may not be ready yet (driver service is still starting
			// or was just reloaded), so retry the connect with a short backoff.
			HRESULT hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
			for (Size attempt = 0; attempt < c_nConnectAttempts; ++attempt)
			{
				hr = ::FilterConnectCommunicationPort(portName.data(), 0, nullptr, 0,
					nullptr, &m_pConnectionPort);
				if (SUCCEEDED(hr))
					break;
				if (attempt + 1 < c_nConnectAttempts)
				{
					LOGLVL(Detailed, "Can't connect to driver port, retrying <" <<
						(attempt + 1) << "> of <" << c_nConnectAttempts << ">");
					::Sleep(c_nConnectBackoffMs);
				}
			}
			if (FAILED(hr))
			{	// TODO: write new Error handler for HRESULT
				// https://blogs.msdn.microsoft.com/oldnewthing/20061103-07/?p=29133
				std::stringstream errorMessage;
				errorMessage  << "Can't open driver connection port<" << string::convertWCharToUtf8(portName) << ">";
				error::win::WinApiError(SL, hr, errorMessage.str().data()).throwException();			
			}

			// Create the IO completion port for asynchronous message passing. 
			m_pCompletionPort.reset(::CreateIoCompletionPort(m_pConnectionPort, nullptr, 0,
				DWORD(threadsCount)));
			if (!m_pCompletionPort)
				error::win::WinApiError(SL, "Can't open driver completion port").throwException();

			// Create listening threads.
			m_pOvlpCtxes.resize(threadsCount);
			for (auto& pCtx : m_pOvlpCtxes)
			{
				pCtx.nDataSize = c_nDefMsgSize;
				pCtx.pData = allocMem(pCtx.nDataSize);
				if (pCtx.pData == nullptr)
					error::BadAlloc(SL, "Can't allocate memory for port message").throwException();
				pumpMessage(&pCtx);
			}

			// Start all threads.
			if (!m_pThreadPool.empty())
				error::InvalidUsage(SL, "Threads pool is not empty").throwException();

			handler = _handler;

			for (Size i = 0; i < threadsCount; ++i)
				m_pThreadPool.push_back(std::thread([this]() { this->parseEventsThread(); }));
		}

		//
		//FltPortReceiver::reconnect
		//

		bool FltPortReceiver::reconnect(size_t nExpectedGen)
		{
			std::scoped_lock _lock(m_mtxReconnect);
			if (m_fTerminate)
				return true;

			// If another thread already restored the connection, there is nothing
			// to do here — the caller just resumes using the new port.
			if (m_nConnGeneration.load() != nExpectedGen)
				return true;

			for (Size attempt = 0; attempt < c_nReconnectAttempts && !m_fTerminate; ++attempt)
			{
				HANDLE hConnectionPort = nullptr;
				HRESULT hr = ::FilterConnectCommunicationPort(portName.data(), 0, nullptr, 0,
					nullptr, &hConnectionPort);
				if (SUCCEEDED(hr))
				{
					HANDLE hCompletionPort = ::CreateIoCompletionPort(hConnectionPort, nullptr, 0,
						DWORD(threadsCount));
					if (hCompletionPort == nullptr)
					{
						error::win::WinApiError(SL, "Can't open driver completion port on reconnect").log();
						::CloseHandle(hConnectionPort);
						break;
					}

					ScopedHandle vNewConnectionPort(hConnectionPort);
					ScopedHandle vNewCompletionPort(hCompletionPort);

					// Swap new handles in. Closing the old connection/completion port
					// cancels the outstanding operations and wakes the other receiving
					// threads (they observe the new connection generation and resume).
					m_pConnectionPort.reset(vNewConnectionPort.release());
					m_pCompletionPort.reset(vNewCompletionPort.release());

					// Give pending operations on the old connection a moment to cancel
					// before re-issuing FilterGetMessage on the new one.
					::Sleep(50);

					// Re-pump every message context on the new connection.
					for (auto& pCtx : m_pOvlpCtxes)
					{
						CMD_TRY
						{
							pumpMessage(&pCtx);
						}
						CMD_PREPARE_CATCH
						catch (error::Exception& e)
						{
							e.log(SL, "Fail to pump message after reconnect");
						}
					}

					++m_nConnGeneration;
					LOGWRN("Fltport connection is restored");
					return true;
				}

				::Sleep(c_nReconnectBackoffMs);
			}

			// The driver port is not reachable yet (e.g. driver is reloading).
			// If another thread restored the connection meanwhile, report success.
			return m_nConnGeneration.load() != nExpectedGen;
		}

		//
		//FltReceiverPort::Stop
		//

		void FltPortReceiver::Stop()
		{
			m_fTerminate = true;

			//  Wake up the listening thread if it is waiting for message 
			//  via GetQueuedCompletionStatus() 
			if (m_pConnectionPort)
				CancelIoEx(m_pConnectionPort, NULL);

			// Wait all threads termination
			for (auto& pThread : m_pThreadPool)
				if (pThread.joinable())
					pThread.join();
			m_pThreadPool.clear();

			m_pOvlpCtxes.clear();
			m_pConnectionPort.reset();
			m_pCompletionPort.reset();
		}

}
}