// SSPIAuthenticate.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


void initSecLib( HINSTANCE& hSec );



PSecurityFunctionTable pf = NULL;

int _tmain(int argc, _TCHAR* argv[])
{
	HINSTANCE hSecLib;
	SecPkgInfo *secPackInfo;
	CtxtHandle cliCtx;

	CredHandle creds;
	CtxtHandle srvCtx;

	//The SEC_WINNT_AUTH_IDENTITY structure allows you to pass a particular user name and password
	//to the run-time library for the purpose of authentication.
	//This parameter can be NULL, which indicates that the default credentials for that package must be used
	SEC_WINNT_AUTH_IDENTITY *nameAndPwd = NULL;
	
	//Load the security.dll
	initSecLib( hSecLib );

	int rc, rcISC;


	SecBufferDesc clientOutputBufferDescription, clientInputBufferDescription;
	SecBuffer clientOutputBuffer, clientInputBuffer;

	SecBufferDesc serverOutputBufferDescription, serverInputBufferDescription;
	SecBuffer serverOutputBuffer, serverInputBuffer;
	

	DWORD ctxReq, ctxAttr;
	DWORD srcctxAttr;

	
	
	rc = (pf->QuerySecurityPackageInfo)( (WCHAR*)"Kerberos", &secPackInfo );
	if(rc != SEC_E_OK)
	{
		printf("Unable to get QuerySecurityPackageInfo for Kerberos Authentication");
		return rc;
	}
	


	TimeStamp useBefore;


	rc = (pf->AcquireCredentialsHandle)( NULL, (WCHAR*)"Kerberos", SECPKG_CRED_BOTH,
		NULL, nameAndPwd, NULL, NULL, &creds, &useBefore );

	if(rc != SEC_E_OK)
	{
		
		if(NULL != nameAndPwd)
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication for %s\\%s", nameAndPwd->Domain, nameAndPwd->User);
		else
			printf("Unable to get AcquireCredentialsHandle for Kerberos Authentication");
		
		
		return rc;
	}





	//These flags are not needed for our simple test, but used as an example
	ctxReq = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE;
	

	


	bool haveInbuffer = false;
	bool haveContext = false;
	bool serverhaveContext = false;
	bool serverSideWorkComplete = false;

	bool AuthComplete = false;
	clientInputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	clientOutputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	serverInputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	serverOutputBuffer.pvBuffer = new unsigned char[secPackInfo->cbMaxToken];
	
	
	//Wait for token While loop is used here because it may take more than one try
	//A.K.A. The InitializeSecurityContext Loop
	while ( AuthComplete == false )
	{
		clientOutputBufferDescription.ulVersion = SECBUFFER_VERSION;
		clientOutputBufferDescription.cBuffers = 1;
		clientOutputBufferDescription.pBuffers = &clientOutputBuffer; // just one buffer
		clientOutputBuffer.BufferType = SECBUFFER_TOKEN; // preping a token here
		clientOutputBuffer.cbBuffer = secPackInfo->cbMaxToken;

		rcISC = (pf->InitializeSecurityContext)( &creds, haveContext? &cliCtx: NULL,
			(WCHAR*)"TAL\\jkannankeril", ctxReq, 0, SECURITY_NATIVE_DREP, haveInbuffer? &clientInputBufferDescription: NULL,
			0, &cliCtx, &clientOutputBufferDescription, &ctxAttr, &useBefore );
		printf( "InitializeSecurityContext(): %08xh\n", rcISC );

	


		// send the output buffer off to the server (Nothing to send because we are doing this example in same process)
		//Instead the server side code will just copy (memecpy) the buffer from client side code.


		//**********BEGING SERVER SIDE CODE


		if(false == serverSideWorkComplete)
		{

			//Pretend we are on the server now
			// prepare to get the authority's response
			serverInputBufferDescription.ulVersion = SECBUFFER_VERSION;
			serverInputBufferDescription.cBuffers = 1;
			serverInputBufferDescription.pBuffers = &serverInputBuffer; // just one buffer
			serverInputBuffer.BufferType = SECBUFFER_TOKEN; // preping a token here

			// receive the client's response (copy in our case)
			serverInputBuffer.cbBuffer = clientOutputBuffer.cbBuffer;
			memcpy(serverInputBuffer.pvBuffer, clientOutputBuffer.pvBuffer, clientOutputBuffer.cbBuffer);
			

			// by now we have an input buffer on server side to use!!!


			//Prep an output buffer on the server
			serverOutputBufferDescription.ulVersion = SECBUFFER_VERSION;
			serverOutputBufferDescription.cBuffers = 1;
			serverOutputBufferDescription.pBuffers = &serverOutputBuffer; // just one buffer
			serverOutputBuffer.BufferType = SECBUFFER_TOKEN; 
			serverOutputBuffer.cbBuffer = secPackInfo->cbMaxToken;

			rc = (pf->AcceptSecurityContext)( &creds, serverhaveContext? &srvCtx: NULL,
				&serverInputBufferDescription, 0, SECURITY_NATIVE_DREP, &srvCtx, &serverOutputBufferDescription, &srcctxAttr,
				&useBefore );
			printf( "AcceptSecurityContext(): %08xh\n", rc );



			// send the output buffer off to client (in our case client will copy data from server buffers)

			
			if (( rc == SEC_E_OK ) && (serverOutputBuffer.cbBuffer == 0))
				serverSideWorkComplete = true;
			
			serverhaveContext = true;


		}
		//**********END SERVER SIDE CODE



		//Now we have data back from the server

		//Any data back from the server? If not we are done.
		if ( rcISC != SEC_I_CONTINUE_NEEDED )
			AuthComplete = true;



		//get the server's response (copy in our case)
		
		// prepare Description
		clientInputBufferDescription.ulVersion = SECBUFFER_VERSION;
		clientInputBufferDescription.cBuffers = 1;
		clientInputBufferDescription.pBuffers = &clientInputBuffer; // just one buffer
		
		
		clientInputBuffer.BufferType = SECBUFFER_TOKEN; 
		clientInputBuffer.cbBuffer = serverOutputBuffer.cbBuffer;
		memcpy(clientInputBuffer.pvBuffer, serverOutputBuffer.pvBuffer, clientInputBuffer.cbBuffer);


		haveInbuffer = true;
		haveContext = true;


		
		puts( "Continuing the InitializeSecurityContext Loop" );
	}//End While

	// we arrive here as soon as InitializeSecurityContext() returns != SEC_I_CONTINUE_NEEDED. 
	//Which means we are done
	if ( rcISC != SEC_E_OK )
	{
		printf( "Oops! ISC() returned %08xh!\n", rcISC );
		return rcISC;
	}


	
	
	// now we try to use the context
	rc = (pf->ImpersonateSecurityContext)( &srvCtx );
	printf( "ImpersonateSecurityContext(): %08xh\n", rc );
	if ( rc != SEC_E_OK )
	{
		printf( "Error! ImpersonateSecurityContext() returns %08xh!\n", rc );
	}
	else
	{
		TCHAR buf[256];
		DWORD bufsiz = sizeof buf;
		GetUserName( buf, &bufsiz );
		_tprintf( _T("user name: \"%s\"\n"), buf );
		(pf->RevertSecurityContext)( &srvCtx );
		printf( "RevertSecurityContext(): %08xh\n", rc );
		GetUserName( buf, &bufsiz );
		_tprintf( _T("user name: \"%s\"\n"), buf );

	}

	
	
	
	(pf->DeleteSecurityContext)( &cliCtx );
	(pf->FreeCredentialHandle)( &creds );
	(pf->FreeCredentialHandle)( &srvCtx );
	(pf->FreeContextBuffer)( secPackInfo );
	FreeLibrary( hSecLib );

	delete(clientInputBuffer.pvBuffer);
	delete(clientOutputBuffer.pvBuffer);
	delete(serverInputBuffer.pvBuffer);
	delete(serverOutputBuffer.pvBuffer);



	return 0;
}

void initSecLib( HINSTANCE& hSec )
{
	PSecurityFunctionTable (*pSFT)( void );

	hSec = LoadLibraryW(_T("security.dll") );
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



