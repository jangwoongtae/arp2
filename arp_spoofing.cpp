#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <winsock2.h>  
#include <ws2tcpip.h>
#include <iptypes.h>
#include <IPHlpApi.h>
#include <pcap.h>
#include <Windows.h>

#pragma comment(lib,"IPHlpApi.lib")
#pragma comment(lib, "ws2_32.lib")

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

using namespace std;

char myGateway[17]; // 내 게이트웨이 아이피
char attackerIp[17]; // 내 아이피
char victimMac[20]; // 피해자 아이피
char attackerMac[20]; // 내 맥

// 내 아이피와 맥 알아오기
static bool getMyIPnMac(int nFamily)
{
	/* 변수들은 IPHlpApi MSDN 읽어보면 나옴

	*/
	DWORD dwRet;
	PIP_ADAPTER_ADDRESSES pAdpAddrs;
	PIP_ADAPTER_ADDRESSES pThis;
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	unsigned long ulBufLen = sizeof(IP_ADAPTER_ADDRESSES);

	pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);
	if (!pAdpAddrs) return false;

	dwRet = GetAdaptersAddresses(nFamily, 0, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdpAddrs);
		pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);

		if (!pAdpAddrs) return false;
	}

	// GetAdapterAddresses 이 함수가 아이피랑 맥을 가져오는 함수 
	dwRet = GetAdaptersAddresses(nFamily, 0, NULL, pAdpAddrs, &ulBufLen); //nFamily 는 ip v4냐 ip v6냐 결정
	if (dwRet != NO_ERROR)
	{
		free(pAdpAddrs);
		return false;
	}

	pThis = pAdpAddrs; // 위에 함수로 받아온걸 pThis 변수에 저장함


	for (pThisAddrs = pThis->FirstUnicastAddress;
		NULL != pThisAddrs;
		pThisAddrs = pThisAddrs->Next)
	{
		if (nFamily == AF_INET)
		{
			struct sockaddr_in* pAddr
				= (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr; // IP 저장 

			cerr << "  IP v4 : " << inet_ntoa(pAddr->sin_addr) << endl;
			memcpy(attackerIp, inet_ntoa(pAddr->sin_addr), 16); // 메모리복사 전역변수에 자신의 아이피 저장해둠
			if (pThis->PhysicalAddressLength != 0) {
				printf("  MAC   : ");
				for (int i = 0; i < (int)pThis->PhysicalAddressLength; i++) { // 맥주소의 길이만큼 루프 
					if (i == (pThis->PhysicalAddressLength - 1))
					{
						printf("%.2X\n", (int)pThis->PhysicalAddress[i]);
						attackerMac[i] = (char)pThis->PhysicalAddress[i]; // 맥 저장
					}
					else
					{
						printf("%.2X-", (int)pThis->PhysicalAddress[i]);
						attackerMac[i] = (char)pThis->PhysicalAddress[i]; // 맥 저장
					}

				}
			}
		}
	}


	free(pAdpAddrs); // 동적할당 헤제

	return true;

}


// 게이트웨이 ip 가져오기
int getGateWayIp()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	//GetAdaptersInfo MSDN 참조

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}
	/* 함수 한번 실행하면 그냥 정보가 알아서 저장되서 오니 출력만 해주면 됨. */
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {

			// 게이트웨이 IP출력
			printf("  Gateway : %s\n", pAdapter->GatewayList.IpAddress.String);

			//게이트 웨이 IP 저장
			memcpy(myGateway, pAdapter->GatewayList.IpAddress.String, 16);
			
			break;

		}
	}
	if (pAdapterInfo)
		free(pAdapterInfo);

}


// 희생자에게 ARP REQUEST 한 후 MAC을 얻어옴
void goArpVictim(unsigned int victim)
{
	unsigned char bVictimMac[6] = { 0, }; // 맥 저장 
	unsigned long uPhyAddrLen = 6; // 맥 길이

	char macBuffer[20] = { 0, }; // 임시 맥 저장소

	//SendARP 는 ARP 패킷을 보내주는 함수 
	if (SendARP(victim, 0, bVictimMac, &uPhyAddrLen) != NO_ERROR){} // 희생자 아이피로 ARP ㄱㄱ

	sprintf_s(macBuffer, 20, "%02X-%02X-%02X-%02X-%02X-%02X",
		bVictimMac[0],
		bVictimMac[1],
		bVictimMac[2],
		bVictimMac[3],
		bVictimMac[4],
		bVictimMac[5]);


	memcpy(victimMac, macBuffer, 20);
	cout << "  Victim Mac : " << macBuffer << endl;
}


void goArpGate(unsigned int gateway)
{
	unsigned char bGatewayMac[6] = { 0, };
	unsigned long uPhyAddrLen = 6;

	char macBuffer[20] = { 0, };

	if (SendARP(gateway, 0, bGatewayMac, &uPhyAddrLen) != NO_ERROR) {}

	sprintf_s(macBuffer, 20, "%02X-%02X-%02X-%02X-%02X-%02X",
		bGatewayMac[0],
		bGatewayMac[1],
		bGatewayMac[2],
		bGatewayMac[3],
		bGatewayMac[4],
		bGatewayMac[5]);

	cout << "  Gateway Mac : " << macBuffer << endl;
}

int main(int argc, char* argv[])
{

	int ch;
	char str[100];
	// 1번
	bool bFlag = getMyIPnMac(AF_INET);
	if (!bFlag) { return -1; }

	//2번

	getGateWayIp();
	printf("Request 날릴 상대방 IP 직접입력 : ");
	scanf("%d", &ch);
	
	switch (ch){
	case 1:
		
		printf("ip 입력 : ");
		scanf("%s",str);
		goArpVictim(inet_addr(str));
		break;
	default:
		goArpVictim(inet_addr(argv[1]));
		break;
	}
	//3번


	 // inet_addr은 문자열을 네트워크 주소로 바꿔주는 역할을함. 상대방 아이피 
	goArpGate(inet_addr(myGateway));

	system("pause");
	return 0;
}