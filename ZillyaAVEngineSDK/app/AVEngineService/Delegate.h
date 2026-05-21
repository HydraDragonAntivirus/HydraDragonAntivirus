#ifndef DELEGATE_H
#define DELEGATE_H

#pragma once
#include "CoreSDK.h"

namespace Zillya
{
	/* Base delegate class */
	template<typename Arg> class DelegateCallbackBase
	{
	public:
		virtual void notify(Arg) = 0;
	};

	template<typename Arg1, typename Arg2, typename Arg3>
	class DelegateParamBase
	{
	public:
		virtual void notify(Arg1, Arg2, Arg3) = 0;
	};

	/* DelegateCallback class for callback functions */
	template<typename T, typename Arg> class DelegateCallback : public DelegateCallbackBase<Arg>
	{
	private:
		T			*_object;
		void		(T::*_member)(Arg);
	public:
		DelegateCallback(T *object, void (T::*member)(Arg))
		{
			this->_object = object;
			this->_member = member;
		}
		virtual void notify(Arg arg)
		{
			(this->_object->*this->_member)(arg);
		}
	};

	template<typename T, typename Arg1, typename Arg2, typename Arg3>
	class DelegateParamCallback : public DelegateParamBase<Arg1, Arg2, Arg3>
	{
	private:
		T			*_object;
		void		(T::*_member)(Arg1, Arg2, Arg3);
	public:
		DelegateParamCallback(T *object, void (T::*member)(Arg1, Arg2, Arg3))
		{
			this->_object = object;
			this->_member = member;
		}
		virtual void notify(Arg1 arg1, Arg2 arg2, Arg3 arg3)
		{
			(this->_object->*this->_member)(arg1, arg2, arg3);
		}
	};

	template<typename Arg> class Delegate
	{
	private:
		DelegateCallbackBase<Arg>	*_delegate_callback;
	public:
		Delegate() 
		{
			this->_delegate_callback = 0;
		}
		~Delegate() 
		{
			if(this->_delegate_callback != 0)
				delete this->_delegate_callback;
		}

		template<typename T> void Connect(T *object, void (T::*callback)(Arg))
		{
			this->_delegate_callback = new DelegateCallback<T, Arg>(object, callback);
		}
		void operator ()(Arg arg)
		{
			_delegate_callback->notify(arg);
		}
	};

	template <typename Arg1, typename Arg2, typename Arg3>
	class DelegateParam
	{
	private:
		DelegateParamBase<Arg1, Arg2, Arg3>	*_delegate_callback;
	public:
		DelegateParam() 
		{
			this->_delegate_callback = 0;
		}
		~DelegateParam() 
		{
			if(this->_delegate_callback != 0)
				delete this->_delegate_callback;
		}

		template<typename T> void Connect(T *object, void (T::*callback)(Arg1, Arg2, Arg3))
		{
			this->_delegate_callback = new DelegateParamCallback<T, Arg1, Arg2, Arg3>(object, callback);
		}
		void operator ()(Arg1 arg1, Arg2 arg2, Arg3 arg3)
		{
			_delegate_callback->notify(arg1, arg2, arg3);
		}
	};
}

#endif //DELEGATE_H