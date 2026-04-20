#pragma once

enum EXCEPTION_VECTOR : unsigned char
{
	ExternalVirtualInterrupt = 0,
	NonMaskableInterrupt = 2,
	FaultTrapException = 3,
	SoftwareInterrupt = 4
};