// SimpleServer.h: interface for the CSimpleServer class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SIMPLESERVER_H__6941AE15_7FD9_451C_965D_077015FA8643__INCLUDED_)
#define AFX_SIMPLESERVER_H__6941AE15_7FD9_451C_965D_077015FA8643__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CSimpleServer  
{
public:
	void Start();
	int SendClientData(char* buff, int buffLen);
	void Stop();
	
	CSimpleServer();
	virtual ~CSimpleServer();

	    SOCKET server;
    SOCKET client;
    sockaddr_in from;
    int fromlen;

private:
	DWORD __stdcall  StartServerThread(void *parent = NULL);


};

#endif // !defined(AFX_SIMPLESERVER_H__6941AE15_7FD9_451C_965D_077015FA8643__INCLUDED_)
