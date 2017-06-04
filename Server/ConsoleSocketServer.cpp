// ConsoleSocketServer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <tchar.h>

#include <time.h>

#include <windows.h>


#define	SECURITY_WIN32 1
#include <security.h>




#include "WinSockServer.h"

PSecurityFunctionTable pf = NULL;

void initSecLib( HINSTANCE& hSec );

int main(int argc, char* argv[])
{
    int nRetCode = 0;	
	int nPortnum = 1225;
	int nBytesRecieved, nBytesWaiting, nBytesSent;


	SEC_WINNT_AUTH_IDENTITY *nameAndPwd = NULL;
	
	//Load the security.dll
	HINSTANCE hSecLib;
	initSecLib( hSecLib );
	
	int rc;
	
	
	SecPkgInfo *secPackInfo;


	printf("Initializing Kerberos Security Package...\r\n", nPortnum);
	rc = (pf->QuerySecurityPackageInfo)( "Kerberos", &secPackInfo );
	if(rc != SEC_E_OK)
	{
		printf("Unable to get QuerySecurityPackageInfo for Kerberos Authentication");
		return rc;
	}



	TimeStamp useBefore;
	CredHandle creds;
	CtxtHandle srvCtx;
	DWORD srcctxAttr;


	rc = (pf->AcquireCredentialsHandle)( NULL, (SEC_CHAR*)"Negotiate", SECPKG_CRED_INBOUND,
		NULL, nameAndPwd, NULL, NULL, &creds, &useBefore );

	if(rc != SEC_E_OK)
	{
		
		if(NULL != nameAndPwd)
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication for %s\\%s", nameAndPwd->Domain, nameAndPwd->User);
		else
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication");
		
		
		return rc;
	}

	
	
	
	
	printf("Starting Socket Server...\r\n", nPortnum);
	
	HANDLE hThread = (HANDLE)CreateThread(NULL,0, SocketServerThread,&nPortnum,0,NULL);
	
	if(NULL== hThread)
	{
		printf("Could not start server \r\n", nPortnum);
		return 1;
	}
       
	
	if (WAIT_TIMEOUT != WaitForSingleObject(hThread, 2000)) //if Server thread returned this quick
	//there was a problem
	{
		printf("Could not start server on port %d\r\n", nPortnum);
		return 1;
	}


	
	
	bool haveInbuffer = false;
	bool haveContext = false;
	bool serverhaveContext = false;
	bool serverSideWorkComplete = false;
	bool haveToken = false;

	SecBufferDesc serverOutputBufferDescription, serverInputBufferDescription;
	SecBuffer serverOutputBuffer, serverInputBuffer;

	bool AuthComplete = false;
	serverInputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	serverOutputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];

	
	
	printf("Server started waiting for data on port %d...\r\n", nPortnum);


	char temp[2048];

	
	
    while(1)
	{
		Sleep(1000);

		
		nBytesRecieved = 0;
		nBytesSent = 0;
		nBytesWaiting = recv(client, temp, 4, MSG_PEEK);

		if(nBytesWaiting < 4)
			continue;


		nBytesRecieved += 
			recv( client, (char *) &serverInputBuffer.cbBuffer, sizeof serverInputBuffer.cbBuffer, 0 );


		if((serverInputBuffer.cbBuffer > secPackInfo->cbMaxToken) || (nBytesRecieved<1))
			continue;


		
		while(nBytesWaiting < (int)serverInputBuffer.cbBuffer)
			nBytesWaiting = recv(client, (char*)serverInputBuffer.pvBuffer, serverInputBuffer.cbBuffer, MSG_PEEK);


		

		nBytesRecieved += recv(client, (char*)serverInputBuffer.pvBuffer, serverInputBuffer.cbBuffer, 0);

		printf("Received Authentication packet %d bytes received...\r\n", nBytesRecieved);
		
		serverInputBufferDescription.ulVersion = SECBUFFER_VERSION;
		serverInputBufferDescription.cBuffers = 1;
		serverInputBufferDescription.pBuffers = &serverInputBuffer; // just one buffer
		serverInputBuffer.BufferType = SECBUFFER_TOKEN; // preping a token here


		serverOutputBufferDescription.ulVersion = SECBUFFER_VERSION;
		serverOutputBufferDescription.cBuffers = 1;
		serverOutputBufferDescription.pBuffers = &serverOutputBuffer; // just one buffer
		serverOutputBuffer.BufferType = SECBUFFER_TOKEN; 
		serverOutputBuffer.cbBuffer = secPackInfo->cbMaxToken;

		
		
		rc = (pf->AcceptSecurityContext)( &creds, serverhaveContext? &srvCtx: NULL,
			&serverInputBufferDescription, 0, SECURITY_NATIVE_DREP, &srvCtx, &serverOutputBufferDescription, &srcctxAttr,
			&useBefore );
		printf( "AcceptSecurityContext(): %08xh\n", rc );


		if ( rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED )
		{
			if ( serverOutputBuffer.cbBuffer != 0 )
			{
				send( client, (const char *) &serverOutputBuffer.cbBuffer, sizeof serverOutputBuffer.cbBuffer, 0 );
				nBytesSent += sizeof serverOutputBuffer.cbBuffer;
				send( client, (const char *) serverOutputBuffer.pvBuffer, serverOutputBuffer.cbBuffer, 0 );
				nBytesSent += serverOutputBuffer.cbBuffer;
				printf("Sending response Bytes sent (%d)...\r\n", nBytesSent);
			}
		}



		if ( rc != SEC_I_CONTINUE_NEEDED )
		{
			printf( "Authentication Handshake complete!\n", rc );
			
			if ( rc != SEC_E_OK )
			{
				printf( "Oops! ASC() returned %08xh!\n", rc );
				continue;
			}


			// now we try to use the context
			rc = (pf->ImpersonateSecurityContext)( &srvCtx );
			printf( "ImpersonateSecurityContext(): %08xh\n", rc );
			if ( rc != SEC_E_OK )
			{
				printf( "Error! ImpersonateSecurityContext() returns %08xh!\n", rc );
				continue;
			}


			TCHAR buf[256];
			DWORD bufsiz = sizeof buf;
			GetUserName( buf, &bufsiz );
			_tprintf( _T("user name: \"%s\"\n"), buf );
			(pf->RevertSecurityContext)( &srvCtx );
			printf( "RevertSecurityContext(): %08xh\n", rc );
			GetUserName( buf, &bufsiz );
			_tprintf( _T("user name: \"%s\"\n"), buf );
			
			printf( "Wating for next client...\n", rc );
			serverhaveContext = false;
			continue;
		}


		
		printf("Waiting for replay..\r\n");
		serverhaveContext = true;
		


	}
	
    (pf->FreeCredentialHandle)( &srvCtx );
	(pf->FreeCredentialHandle)( &creds );
	(pf->FreeContextBuffer)( secPackInfo );
	FreeLibrary( hSecLib );
	
	return nRetCode;
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

