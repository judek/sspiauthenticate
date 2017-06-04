// SimpleServer.cpp: implementation of the CSimpleServer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SimpleServer.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CSimpleServer::CSimpleServer()
{
	int fromlen=sizeof(from);

}

CSimpleServer::~CSimpleServer()
{

}


	
DWORD __stdcall  CSimpleServer::StartServerThread(void *parent)
{

	return 1;
}



int CSimpleServer::SendClientData(char *buff, int buffLen)
{

	return send(client,buff,buffLen,0);
}

void CSimpleServer::Start()
{
	
	//CreateThread(NULL,0, StartServerThread,NULL,0,NULL);

}
