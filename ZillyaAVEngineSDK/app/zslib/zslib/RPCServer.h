#pragma once

#include "zsdk_def.h"

class RPCServer
{
public:
	virtual ~RPCServer(void);

	virtual void Listen() = 0;
};
