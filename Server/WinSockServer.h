#include <winsock2.h> 

//note: "ws2_32.lib" Must be linked to your project

//Globals
SOCKET server;
SOCKET client;
DWORD __stdcall  SocketServerThread(void *pnPortnum);


//Server Thread
DWORD __stdcall  SocketServerThread(void *pnPortnum)
{	
    
	sockaddr_in from;
	int fromlen=sizeof(from);
	WSADATA wsaData;
	int* pPort = (int*)pnPortnum;
    sockaddr_in local;
    int wsaret=WSAStartup(0x101,&wsaData);


    if(wsaret!=0)
    {
        return 0;
    }

    //Now we populate the sockaddr_in structure
    local.sin_family=AF_INET; //Address family
    local.sin_addr.s_addr=INADDR_ANY; //Wild card IP address
    local.sin_port=htons((u_short)*pPort); //port to use

    //the socket function creates our SOCKET
    server=socket(AF_INET,SOCK_STREAM,0);

    //If the socket() function fails we exit
    if(server==INVALID_SOCKET)
    {
        return 0;
    }

    if(bind(server,(sockaddr*)&local,sizeof(local))!=0)
    {
        return 0;
    }


    if(listen(server,10)!=0)
    {
        return 0;
    }


    while(true)
       client=accept(server,(struct sockaddr*)&from,&fromlen);
  
       
    return 0;
}


