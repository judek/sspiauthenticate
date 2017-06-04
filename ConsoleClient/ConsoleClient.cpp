// ConsoleClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <winsock2.h>

#include <time.h>
#include <string.h>

#include <windows.h>


#define	SECURITY_WIN32 1
#include <security.h>

PSecurityFunctionTable pf = NULL;

void initSecLib( HINSTANCE& hSec );


int _tmain(int argc, _TCHAR* argv[])
{

	int nPortnum = 1225;

	WSADATA wsaData;
	int* pPort = (int*)&nPortnum;
    int wsaret=WSAStartup(0x101,&wsaData);

    if(wsaret!=0)
    {
        return 0;
    }

	SOCKET conn;
	conn=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(conn==INVALID_SOCKET)
		return 0;


	hostent* hp=gethostbyname("localhost");
    if(NULL == hp)
    {
        return -1;
    }

	sockaddr_in server;

	server.sin_addr.s_addr=*((unsigned long*)hp->h_addr);
	server.sin_family=AF_INET;
	server.sin_port=htons(nPortnum);
	if(connect(conn,(struct sockaddr*)&server,sizeof(server)))
	{
		closesocket(conn);
		return -1;	
	}

/*
	TCHAR NameDomain[256];
	wcscpy(NameDomain, "TAL\\");
	int DomainLength = (int)wcslen(NameDomain);
	DWORD NameDomainsiz = (sizeof(NameDomain) - DomainLength);
	GetUserName( NameDomain + DomainLength, &NameDomainsiz );
*/

	HINSTANCE hSecLib;
	SecPkgInfo *secPackInfo;
	CtxtHandle cliCtx;

	CredHandle creds;


	//The SEC_WINNT_AUTH_IDENTITY structure allows you to pass a particular user name and password
	//to the run-time library for the purpose of authentication.
	//This parameter can be NULL, which indicates that the default credentials for that package must be used
	SEC_WINNT_AUTH_IDENTITY *nameAndPwd = NULL;
	
	//Load the security.dll
	initSecLib( hSecLib );

	int rc, rcISC;


	SecBufferDesc clientOutputBufferDescription, clientInputBufferDescription;
	SecBuffer clientOutputBuffer, clientInputBuffer;


	DWORD ctxReq, ctxAttr;


	rc = (pf->QuerySecurityPackageInfo)( "Kerberos", &secPackInfo );
	if(rc != SEC_E_OK)
	{
		printf("Unable to get QuerySecurityPackageInfo for Kerberos Authentication");
		return rc;
	}



	TimeStamp useBefore;


	rc = (pf->AcquireCredentialsHandle)( NULL, "Kerberos", SECPKG_CRED_OUTBOUND,
		NULL, nameAndPwd, NULL, NULL, &creds, &useBefore );


	if(rc != SEC_E_OK)
	{
		
		if(NULL != nameAndPwd)
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication for %s\\%s", nameAndPwd->Domain, nameAndPwd->User);
		else
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication");
		
		
		return rc;
	}


	ctxReq = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH;
	//ctxReq = 0;


	bool haveInbuffer = false;
	bool haveContext = false;

	int nBytesSent = 0;
	int nBytesWaiting = 0;
	int nBytesRecieved = 0;

	bool AuthComplete = false;
	clientInputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	clientOutputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];

	while ( AuthComplete == false )
	{

		nBytesSent = 0;
		nBytesWaiting = 0;
		nBytesRecieved = 0;

		clientOutputBufferDescription.ulVersion = SECBUFFER_VERSION;
		clientOutputBufferDescription.cBuffers = 1;
		clientOutputBufferDescription.pBuffers = &clientOutputBuffer; // just one buffer
		clientOutputBuffer.BufferType = SECBUFFER_TOKEN; // preping a token here
		clientOutputBuffer.cbBuffer = secPackInfo->cbMaxToken;

		//Very important, this is the server princeable name we are connecting to we need to know that
		//"TAL\\dw3-jkannankeril$"
		
		rcISC = (pf->InitializeSecurityContext)( &creds, haveContext? &cliCtx: NULL,
			"TAL\\dw3-jkannankeril$", ctxReq, 0, SECURITY_NATIVE_DREP, haveInbuffer? &clientInputBufferDescription: NULL,
			0, &cliCtx, &clientOutputBufferDescription, &ctxAttr, &useBefore );
		
		printf( "InitializeSecurityContext(): %08xh\n", rcISC );


		if ( clientOutputBuffer.cbBuffer != 0 )
		{
			send( conn, (const char *) &clientOutputBuffer.cbBuffer, sizeof clientOutputBuffer.cbBuffer, 0 );
			nBytesSent += sizeof clientOutputBuffer.cbBuffer;
			send( conn, (const char *) clientOutputBuffer.pvBuffer, clientOutputBuffer.cbBuffer, 0 );
			nBytesSent += clientOutputBuffer.cbBuffer;
			printf("Sending Bytes sent (%d)...\r\n", nBytesSent);
		}


		if ( rcISC != SEC_I_CONTINUE_NEEDED )
			break;



		clientInputBufferDescription.ulVersion = SECBUFFER_VERSION;
		clientInputBufferDescription.cBuffers = 1;
		clientInputBufferDescription.pBuffers = &clientInputBuffer; // just one buffer
		clientInputBuffer.BufferType = SECBUFFER_TOKEN; // preping a token here



		nBytesWaiting = 0;
		while(nBytesWaiting < 4)
		{
			nBytesWaiting += recv( conn, (char *) &clientInputBuffer.cbBuffer, sizeof clientInputBuffer.cbBuffer, MSG_PEEK );
			Sleep(1000);
		}

		
		nBytesRecieved += recv( conn, (char *) &clientInputBuffer.cbBuffer, sizeof clientInputBuffer.cbBuffer, 0 );
		
		if((clientInputBuffer.cbBuffer > secPackInfo->cbMaxToken) || (nBytesRecieved<1))
		{
			printf("Incoming buffer out of range with a size of %d\n", clientInputBuffer.cbBuffer);
			break;
		}


		while(nBytesWaiting < (int)clientInputBuffer.cbBuffer)
		{
			nBytesWaiting = recv(conn, (char*)clientInputBuffer.pvBuffer, clientInputBuffer.cbBuffer, MSG_PEEK);
			Sleep(1000);
		}



		nBytesRecieved += recv(conn, (char*)clientInputBuffer.pvBuffer, clientInputBuffer.cbBuffer, 0);

		printf("Received Authentication packet %d bytes received...\r\n", nBytesRecieved);
		
		
		
		haveInbuffer = true;
		haveContext = true;

	
	
	
	
	}



	printf("Press any key to quit\n");
	getchar();






	return 0;
}


void initSecLib( HINSTANCE& hSec )
{
	PSecurityFunctionTable (*pSFT)( void );

	hSec = LoadLibrary(_T("security.dll") );
	pSFT = (PSecurityFunctionTable (*)( void )) GetProcAddress( hSec, "InitSecurityInterfaceA" );
	if ( pSFT == NULL )
	{
		puts( "security.dll load messed up ..." );
		return;
	}

	pf = pSFT();
	if ( pf == NULL )
	{
		puts( "no function table?!?" );
		return;
	}
}

