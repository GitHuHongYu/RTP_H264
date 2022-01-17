#include "main.h"

using namespace std;
#pragma comment(lib,"ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS

deque<rtpBuf> rtpPackList;//rtp������

void hex_dump(const void* buf, int len)
{
	int i = 0;
	unsigned char* p = (unsigned char*)buf;

	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i == 0)
				printf("%08X ", (long)(p + i));
			else
				printf("\n%08X ", (long)(p + i));
		}
		printf("%02X ", p[i]);
	}
	printf("\n--------------------------------------------------------------\n");
}

void get_data_value(char* data, const char* value, char *str)
{
	char *p;

	p = strstr(data, value);
	if (p != NULL)
	{
		if (value == "realm")
		{
			sscanf(p, "realm=\"%[^\"]", str);
		}
		if (value == "nonce")
		{
			sscanf(p, "nonce=\"%[^\"]", str);
		}
		if (value == "Session")
		{
			sscanf(p, "Session: %[^;]", str);
		}
	}
	else
	{
		printf("tan90�� value : %s", value);
	}

	int len = strlen(str);
	str[len] = '\0';
	//cout << value << " = " << str << endl;
}

int create_rtsp_tcp_connect(SOCKET &sock, sockaddr_in &sockAddr, int port)
{
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == sock) {
		printf("Socket() error:%d", WSAGetLastError());
		return -1;
	}

	sockAddr.sin_port = htons(port);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("192.168.8.250");

	//�������������������
	if (connect(sock, (sockaddr*)&sockAddr, sizeof(sockAddr)) == -1) {
		printf("Connect failed:%d", WSAGetLastError());
		return -1;
	}

	return 0;
}

int create_rtp_udp_connect(SOCKET& sock, sockaddr_in& sockAddr, int port)
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);//����RTPͨ�ŵ�socket
	if (SOCKET_ERROR == sock) {
		printf("Socket() error:%d", WSAGetLastError());
		return -1;
	}

	sockAddr.sin_port = htons(port);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("192.168.8.233");

	if (bind(sock, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) == -1)//�󶨱��ض˿�
	{
		cout << "Bind to local machine error" << endl;
		return -1;
	}
	else
	{
		cout << "Bind to local machine ok" << endl;
	}

	return 0;
}

int create_send_rtp_udp_connect(SOCKET& sock, sockaddr_in& sockAddr, int port)
{
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//����RTPͨ�ŵ�socket
	if (SOCKET_ERROR == sock) {
		printf("Socket() error:%d", WSAGetLastError());
		return -1;
	}

	sockaddr_in addr;
	addr.sin_port = htons(1234);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
		printf("setsockopt error\n");
		return -1;
	}
	if (bind(sock, (const struct sockaddr*)&addr, sizeof(addr))< 0)
	{
		closesocket(sock);
		printf("bind error\n");
		return -1;
	}

	sockAddr.sin_port = htons(port);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("192.168.8.233");//172.16.19.32

	return 0;
}

//return: ���յ������ݳ���
/*
���͸���������ɹ����᷵��״̬��200 OK
״̬�루Status-Code����һ����λ���������������������շ������յ�������Ϣ��ִ�н����
Status-Code�ĵ�һλ����ָ��������ظ���Ϣ�����࣬һ����5�ࣺ
 1XX: Informational �C ���󱻽��յ�����������
 2XX: Success �C ���󱻳ɹ��Ľ��գ�����������
 3XX: Redirection �C Ϊ���������Ҫ����Ĳ���
 4XX: Client Error �C ������Ϣ�а����﷨������ǲ��ܹ�����Чִ��
 5XX: Server Error �C ��������Ӧʧ�ܣ��޷�������ȷ����Ч��������Ϣ
*/
int recvData(SOCKET& sock, char *recvBuf, bool printFlag)
{
	SOCKADDR_IN sockAddr;
	socklen_t addrLen = sizeof(sockAddr);

	int len = recvfrom(sock, recvBuf, RTP_RECV_DATA_LEN, 0, (SOCKADDR*)&sockAddr, &addrLen);
	if (len > 0)
	{
		if (printFlag)//�Ƿ��ӡ
		{
			recvBuf[len] = '\0';
			printf("���յ�����len = %d\n%s\n", len, recvBuf);
		}
	}
	else
	{
		printf("recvfrom Error\n");
	}
	return len;
}

/*
������֤�����response����������MD5���ܣ�digest/response ���㷽��
	hs1 = md5hash(username + ":" + realm + ":" + password)
	hs2 = md5hash(method + ":" + requestUri)
	response = md5hash(hs1 + ":" + nonce + ":" + hs2)

	username���û���
	password�� ����
	realm�� ͨ��һ�� server ��Ӧһ�� realm
	method�����󷽷���OPTIONS/DESCRIBE/SETUP/PLAY��
	requestUri�� ����� uri
	nonce�� ����ַ�����ͨ��һ�� session ��Ӧһ�� nonce
*/
string md5ToResponse(string realm, string nonce, string method, string url)
{
	string buf1 = string("admin:" + string(realm) + ":huiyuan123");
	string md5_1 = MD5(buf1).toStr();
	string buf2 = string(method + ":" + url);
	string md5_2 = MD5(buf2).toStr();
	string response = MD5(md5_1 + ":" + nonce + ":" + md5_2).toStr();
	//cout << "md5 = " << response << endl;
	return response;
}

int options(SOCKET &sock, sockaddr_in &sockAddr)
{
	cout << "============================================OPTIONS============================================" << endl;
	char sendBuf[1024];
	snprintf(sendBuf, 1024,
		"OPTIONS rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 2\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"\r\n");
	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));

	return 0;
}

//��һ�η���describe�᷵��401��ʾ��֤
int describe(SOCKET& sock, sockaddr_in& sockAddr)
{
	cout << "============================================DESCRIBE============================================" << endl;
	char sendBuf[1024];
	snprintf(sendBuf, 1024,
		"DESCRIBE rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 3\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"Accept: application/sdp\r\n"
		"\r\n");
	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
	return 0;
}

//����401ʱ��Ҫ�ͻ�����֤
int describe_authorization(SOCKET& sock, sockaddr_in& sockAddr, char *realm, char *nonce, const char *response)
{
	cout << "============================================DESCRIBE_AUTHORIZATION============================================" << endl;
	char sendBuf[1024];
	snprintf(sendBuf, 1024,
		"DESCRIBE rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 4\r\n"
		"Authorization: Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1\", response=\"%s\"\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"Accept: application/sdp\r\n"
		"\r\n",
		realm, nonce, response);

	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
	return 0;
}

int setup(SOCKET& sock, sockaddr_in& sockAddr, char* realm, char* nonce, const char* response)
{
	cout << "============================================SETUP============================================" << endl;
	char sendBuf[1024];
	/*
		trackID=1ͨ��
	*/
	snprintf(sendBuf, 1024,
		"SETUP rtsp://192.168.8.250:554/Streaming/Channels/101/trackID=1?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 5\r\n"
		"Authorization: Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"rtsp://192.168.8.250:554/Streaming/Channels/101/\", response=\"%s\"\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"Transport: RTP/AVP;unicast;client_port=23332-23333\r\n"
		"\r\n",
		realm, nonce, response);

	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
	return 0;
}

int play(SOCKET& sock, sockaddr_in& sockAddr, char* realm, char* nonce, const char* response, char *session)
{
	cout << "============================================PLAY============================================" << endl;
	char sendBuf[1024];
	snprintf(sendBuf, 1024,
		"PLAY rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 6\r\n"
		"Authorization: Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"rtsp://192.168.8.250:554/Streaming/Channels/101/\", response=\"%s\"\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"Session: %s\r\n"
		"Range: npt=0.000-\r\n"
		"\r\n",
		realm, nonce, response, session);

	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
	return 0;
}

int teardown(SOCKET& sock, sockaddr_in& sockAddr, char* realm, char* nonce, const char* response, char* session)
{
	cout << "============================================TEARDOWN============================================" << endl;
	char sendBuf[1024];
	snprintf(sendBuf, 1024,
		"TEARDOWN rtsp://192.168.8.250:554/Streaming/Channels/101/?transportmode=unicast&profile=Profile_1 RTSP/1.0\r\n"
		"CSeq: 7\r\n"
		"Authorization: Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"rtsp://192.168.8.250:554/Streaming/Channels/101/\", response=\"%s\"\r\n"
		"User-Agent: LibVLC/3.0.12 (LIVE555 Streaming Media v2016.11.28)\r\n"
		"Session: %s\r\n"
		"\r\n",
		realm, nonce, response, session);

	//printf("sendBuf :\n%s\n", sendBuf);

	sendto(sock, sendBuf, strlen(sendBuf), 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
	return 0;
}

void assembleRtpToH264()
{
	unsigned int i = 0, count = 1;
	unsigned char h264Flag[5] = { 0 };
	rtpBuf buf;
	memset(buf.rtpPackBuf, 0, sizeof(buf.rtpPackBuf));
	
	while(1)
	{
		if (rtpPackList.empty() == false)//�����Ϊ��
		{
			buf = rtpPackList.front();//���Ӷ�ͷԪ��
			rtpPackList.pop_front();//ɾ����ͷԪ��
			//printf("len = %d\n", buf.len);
			//hex_dump(buf.rtpPackBuf, buf.len);

			/* ��ʼ����RTP���� */
			rtpPack.header.v = (buf.rtpPackBuf[0] >> 6) & 0x03;
			rtpPack.header.p = (buf.rtpPackBuf[0] >> 5) & 0x01;
			rtpPack.header.x = (buf.rtpPackBuf[0] >> 4) & 0x01;
			rtpPack.header.cc = buf.rtpPackBuf[0] & 0x0f;
			rtpPack.header.m = (buf.rtpPackBuf[1] >> 7) & 0x01;
			rtpPack.header.pt = buf.rtpPackBuf[1] & 0x7f;
			rtpPack.header.seqNum = ((buf.rtpPackBuf[2] & 0xff) << 8) | (buf.rtpPackBuf[3] & 0xff);
			rtpPack.header.timestamp = ((buf.rtpPackBuf[4] & 0xff) << 24) | ((buf.rtpPackBuf[5] & 0xff) << 16) | ((buf.rtpPackBuf[6] & 0xff) << 8) | (buf.rtpPackBuf[7] & 0xff);
			rtpPack.header.ssrc = ((buf.rtpPackBuf[8] & 0xff) << 24) | ((buf.rtpPackBuf[9] & 0xff) << 16) | ((buf.rtpPackBuf[10] & 0xff) << 8) | (buf.rtpPackBuf[11] & 0xff);
			//printf("%d %d %d %d %d %d %u %u %u\n", 
			//		rtpPack.header.v,
			//		rtpPack.header.p,
			//		rtpPack.header.x,
			//		rtpPack.header.cc,
			//		rtpPack.header.m,
			//		rtpPack.header.pt,
			//		rtpPack.header.seqNum,
			//		rtpPack.header.timeStamp,
			//		rtpPack.header.ssrc);

			rtpPack.payload.fu_indicator.f = (buf.rtpPackBuf[12] >> 7) & 0x01;
			rtpPack.payload.fu_indicator.nri = (buf.rtpPackBuf[12] >> 5) & 0x03;
			rtpPack.payload.fu_indicator.type = buf.rtpPackBuf[12] & 0x1f; //��ʾNALU����
			rtpPack.payload.fu_header.s = (buf.rtpPackBuf[13] >> 7) & 0x01;
			rtpPack.payload.fu_header.e = (buf.rtpPackBuf[13] >> 6) & 0x01;
			rtpPack.payload.fu_header.r = (buf.rtpPackBuf[13] >> 5) & 0x01;
			rtpPack.payload.fu_header.type = buf.rtpPackBuf[13] & 0x1f;//
			//printf("FU_indicator:%d %d %d\nFU_header:%d %d %d %d\n",
			//		rtpPack.payload.fu_indicator.f,
			//		rtpPack.payload.fu_indicator.nri,
			//		rtpPack.payload.fu_indicator.type,
			//		rtpPack.payload.fu_header.s,
			//		rtpPack.payload.fu_header.e,
			//		rtpPack.payload.fu_header.r,
			//		rtpPack.payload.fu_header.type);
			  		
			rtpPack.payload.data = &(buf.rtpPackBuf[12]);//�õ���Ƶ���ݣ�����1�ֽ�FU_indicator��1�ֽ�FU_header��SEI��SPS��PPSû��FU_header��
			//cout << "��Ƶ����: " << endl;
			//hex_dump(rtpPack.payload.data, buf.len-12); 

			int dataLen = buf.len - 12;//��ȥ12�ֽ�RTPͷ��Ϣ����
			int addLen = 0;//����λ����
			unsigned char nal;
			if (1 == rtpPack.header.p)//p��λ��ʾ�и���λ
			{
				addLen = rtpPack.payload.data[dataLen - 1];//�õ�����λ���ȣ�payload���һ���ֽ�Ϊ����λ����
				dataLen -= addLen;//��ȥ����λ
			}

			if (1 == rtpPack.payload.fu_indicator.type)//P֡
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x61;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //��ȥ1�ֽ�FU_indicator��ʣ���ΪSEI����
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data��1��ʼ��ȥ��FU_indicator����
			}
			else if (6 == rtpPack.payload.fu_indicator.type)//SEI
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x06;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //��ȥ1�ֽ�FU_indicator��ʣ���ΪSEI����
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data��1��ʼ��ȥ��FU_indicator����
			}
			else if (7 == rtpPack.payload.fu_indicator.type)//SPS
			{
				//printf("SPS dataLen = %d\n", dataLen);
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x67;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //��ȥ1�ֽ�FU_indicator��ʣ���ΪSPS����
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data��1��ʼ��ȥ��FU_indicator����
			}
			else if (8 == rtpPack.payload.fu_indicator.type)//PPS
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x68;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //��ȥ1�ֽ�FU_indicator��ʣ���ΪPPS����
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data��1��ʼ��ȥ��FU_indicator����
			}
			else if (24 == rtpPack.payload.fu_indicator.type)//STAP-A
			{
				printf("STAP-A:��һʱ�����ϰ�\n");
			}
			else if (25 == rtpPack.payload.fu_indicator.type)//STAP-B
			{
				printf("STAP-B:��һʱ�����ϰ�\n");
			}
			else if (26 == rtpPack.payload.fu_indicator.type)//MTAP16
			{
				printf("MTAP16:���ʱ�����ϰ�\n");
			}
			else if (27 == rtpPack.payload.fu_indicator.type)//MTAP24
			{
				printf("MTAP24:���ʱ�����ϰ�\n");
			}
			else if (28 == rtpPack.payload.fu_indicator.type)//FU_A
			{
				nal = (rtpPack.payload.fu_indicator.f << 7) | (rtpPack.payload.fu_indicator.nri << 5) | rtpPack.payload.fu_header.type;
				dataLen -= 2; //��ȥ1�ֽ�FU_indicator��1�ֽ�FU_header,ʣ���Ϊh264����
				if (0 == rtpPack.header.m)//maker = 0 ��Ƭ���������һ��
				{
					if (1 == rtpPack.payload.fu_header.s)//s = 1 ��Ƭ����һ��
					{
						h264Flag[0] = 0x00;
						h264Flag[1] = 0x00;
						h264Flag[2] = 0x00;
						h264Flag[3] = 0x01;
						h264Flag[4] = nal;
						fwrite(h264Flag, 1, 5, fRtpToH264);
						fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data��2��ʼ��ȥ��FU_indicator��FU_header����
					}
					else//s == 0 && e == 0��Ƭ���м��
					{
						fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data��2��ʼ��ȥ��FU_indicator��FU_header����
					}
				}
				else//maker = 1 ��Ƭ�����һ��
				{
					fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data��2��ʼ��ȥ��FU_indicator��FU_header����
				}
			}
			else if (29 == rtpPack.payload.fu_indicator.type)//FU_B
			{
				printf("FU_B:��Ƭ��B\n");
			}
			else
			{
				printf("This pack is error!\n");
			}

			if ((rtpPack.header.seqNum - i) == 1)
				cout << "rtp.seqNum: " << rtpPack.header.seqNum << endl;
			else
				cout << "��ǰseqNum����һ��seqNum��Ϊ1" << endl;
			i = rtpPack.header.seqNum;

			if (count++ >= RTP_PACK_NUM)//����ָ������
				break;

			memset(buf.rtpPackBuf, 0, sizeof(buf.rtpPackBuf));
		}
	}
}

/* �ж��Ƿ�Ϊ��ʼ��: 00 00 00 01 */
bool isStartCode(unsigned char* buf)
{
	if ((0 == buf[0]) && (0 == buf[1]) && (0 == buf[2]) && (1 == buf[3]))
	{
		return true;
	}
	return false;
}

/* ��ȡH264��һ��NALU��Ԫ����00 00 00 00 01��ʼ������һ��00 00 00 01������buf�в�������ʼ�루1�ֽڰ���NALUͷ����Ƶ���ݣ� */
int getNALU(unsigned char* buf)
{
	unsigned int pos;//�����ļ�ָ�뵱ǰƫ��ֵ
	unsigned char* naluBuf;

	naluBuf = (unsigned char*)calloc(NALU_BUFFER, sizeof(char));//����1M�ռ䣬�洢һ֡����
	if (NULL == naluBuf)
	{
		printf("calloc naluBuff failed!\n");
		return -1;
	}

	int len = fread(naluBuf, 1, 4, fH264ToRtp);//H264�ļ���ʼ��4���ֽ�Ӧ��Ϊ00 00 00 01
	if (4 != len)
	{
		free(naluBuf);
		return -1;
	}
	pos = 4;
	if (!isStartCode(naluBuf))
	{
		printf("No start code is found.\n");
		free(naluBuf);
		return -1;
	}

	unsigned int index = 0;
	bool startCodeFlag = false;
	while (1)
	{
		if (feof(fH264ToRtp))//�ж��Ƿ����ļ�β
		{
			memcpy(buf, &naluBuf[4], pos - 5);
			free(naluBuf);
			return pos - 5;
		}
		if (pos > NALU_BUFFER)
		{
			printf("NALU data len > MaxNaluBuffer.\n");
			return -1;
		}

		naluBuf[pos++] = fgetc(fH264ToRtp);//���ļ�ָ�뵱ǰλ�ö�һ���ֽڣ��ļ�ָ������ƫ��һλ
		startCodeFlag = isStartCode(&naluBuf[pos - 4]);//����Ƿ�����һ����ʼ��
		if (startCodeFlag)
			break;
	}

	if (0 != fseek(fH264ToRtp, -4, SEEK_CUR))//�����ļ�ָ�����ƫ��4�ֽڣ�4�ֽڿ�ʼ�룩���ɹ�����0
	{
		printf("set fseek failed!\n");
		free(naluBuf);
		return -1;
	}

	//����һ������NALU��������ǰ�����ʼ��00 00 00 01����ǰ��naluBuf�а���������ʼ��
	int naluDataLen = pos - 8;//������ʼ���ܳ�Ϊ8
	memcpy(buf, &naluBuf[4], naluDataLen);//naluBuf[4]���Թ���һ�����ʼ��

	free(naluBuf);
	return naluDataLen;
}

void splitH264ToRtp()
{
	int ret;
	unsigned int len, timestamp_increase = 0, timestamp = 0;
	unsigned int seq_num = 1;
	unsigned char* naluData;//����һ��NALU��Ԫ�����ݣ���������ʼ��00 00 00 01��
	naluData = (unsigned char*)calloc(NALU_BUFFER, sizeof(char));//����1M�ռ䣬�洢һ֡����
	if (NULL == naluData)
	{
		printf("calloc naluData failed!\n");
		return;
	}

	timestamp_increase = (unsigned int)(90000.0 / FRAMERATE);

	while (!feof(fH264ToRtp))//ÿ��ѭ������һ����ʼ�뵽��һ����ʼ�������
	{
		len = getNALU(naluData);
		if (len < 0)
		{
			printf("Get NALU Error.\n");
			continue;
		}

		nalu.f = (naluData[0] >> 7) & 0x01;
		nalu.nri = (naluData[0] >> 5) & 0x03;
		nalu.type = naluData[0] & 0x1f;
		rtp_header = (RTP_FIXED_HEADER*)&sendBuf.rtpPackBuf[0];//��sendBuf�е�ǰ12�ֽ�ǿתΪRTP��12�ֽڹ̶�ͷ
		rtp_header->v = 2;
		rtp_header->p = 0;
		rtp_header->x = 0;
		rtp_header->cc = 0;
		rtp_header->m = 0;
		rtp_header->pt = H264;
		rtp_header->ssrc = htonl(12345678);//���ָ��

		if ((7 == nalu.type) || (1 == nalu.type))//����ʱ�����SPS��PPS��SEI��I֡����ͬ
		{
			timestamp += timestamp_increase;
			rtp_header->timestamp = htonl(timestamp);
		}

		printf("nalu.type : %x, timestamp : %u, data[0] : %2X, len : %u\n", nalu.type, timestamp, naluData[0], len);
		if (len <= 1400)//��������
		{
			if ((6 != nalu.type) && (7 != nalu.type) && (8 != nalu.type))//SPS��PPS��SEI��marker�����Ϊһ֡�Ľ���
			{
				rtp_header->m = 1;
			}
			rtp_header->seqNum = htons(seq_num++);//htons htonl�������ֽ���ת�������ֽ��򣨴��ģʽ��,�����ֽڵ�������

			sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | nalu.type;//������FU_indicator
			memcpy(&sendBuf.rtpPackBuf[13], &naluData[1], len-1);//naluData[1]ȥ��NALUͷ
			sendBuf.len = 12 + len;
			ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
			//if (ret != SOCKET_ERROR)
			//	cout << "�������ͳɹ� : " << ret << endl;
			//else
			//	cout << "��������ʧ��" << endl;
		}
		else if (len > 1400)//FU_A�ְ�
		{
			int count, lastLen, nowCount = 0;//lastLen����ĩβ��ʣ��ĳ��ȣ�nowCount���浱ǰ���͵İ�
			count = len / 1400;//�����ж��ٸ���
			lastLen = len % 1400;//���һ�����ݵ��ֽڳ���

			while (nowCount <= count)
			{
				rtp_header->seqNum = htons(seq_num++);
				if (0 == nowCount)//��Ƭ���ĵ�һ��
				{
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (1 << 7) | (0 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[1], 1400-1);//naluData[1]ȥ��NALUͷ
					sendBuf.len = 14 + 1400 - 1;//12RTPͷ+FU_indicator+FU_Header+1400-NALUͷ
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "��һ�����ͳɹ� : " << ret << endl;
					//else
					//	cout << "��һ������ʧ��" << endl;

				}
				else if (nowCount == count)//���һ��
				{
					rtp_header->m = 1;
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (0 << 7) | (1 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[nowCount*1400], lastLen);
					sendBuf.len = 14 + lastLen;//12RTPͷ+FU_indicator+FU_Header+lastLen
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "���һ�����ͳɹ� : " << ret << endl;
					//else
					//	cout << "���һ������ʧ��" << endl;
				}
				else//�м��
				{
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (0 << 7) | (0 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[nowCount*1400], 1400);
					sendBuf.len = 14 + 1400;//12RTPͷ+FU_indicator+FU_Header+1400
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "�м�����ͳɹ� : " << ret << endl;
					//else
					//	cout << "�м������ʧ��" << endl;

				}
				cout << sendBuf.len << " ";
				nowCount++;
			}
			cout << endl;
		}
		_sleep(50);//����һ֡��ʱ����ֹ���췢����
	}
	free(naluData);
}

#define RTP_TO_H264 0
#define H264_TO_RTP 1

int main()
{
	WSADATA WSAData;

	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("��ʼ��ʧ��!");
		return -1;
	}

#if RTP_TO_H264
	/* ����������������ͷ��RTP���ݣ��ȴ���TCPSocket����RTSPͨ�ţ��ٴ���UDPSocket����RTP���ݣ�Ȼ�����RTP���ݲ������ļ� */
	fRtpToH264 = fopen(H264_FILENAME, "wb+");//�����Զ����Ƶķ�ʽ���ļ������ı���ʽ�򿪻��Զ����0x0d('\n')�����²��Ż���
	if (NULL == fRtpToH264)
	{
		cout << "���ļ�ʧ��" << endl;
	}

	create_rtsp_tcp_connect(rtspTcpClientSocket, rtspSockAddr, RTSP_CLIENT_PORT);

	/* 1.OPTIONS */
	options(rtspTcpClientSocket, rtspSockAddr);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 2.DESCRIBE */
	describe(rtspTcpClientSocket, rtspSockAddr);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 3.DESCRIBE��֤ */
	char realm[32], nonce[64];//��ȡrealm��nonce
	get_data_value(recvBuf.rtpPackBuf, "realm", realm);
	get_data_value(recvBuf.rtpPackBuf, "nonce", nonce);
	string response = md5ToResponse(string(realm), string(nonce), "DESCRIBE", "rtsp://192.168.8.250:554/Streaming/Channels/101?transportmode=unicast&profile=Profile_1");
	describe_authorization(rtspTcpClientSocket, rtspSockAddr, realm, nonce, response.c_str());
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 4.SETUP */
	response = md5ToResponse(string(realm), string(nonce), "SETUP", "rtsp://192.168.8.250:554/Streaming/Channels/101/");
	setup(rtspTcpClientSocket, rtspSockAddr, realm, nonce, response.c_str());
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 5.PLAY */
	char session[16];
	get_data_value(recvBuf.rtpPackBuf, "Session", session);
	response = md5ToResponse(string(realm), string(nonce), "PLAY", "rtsp://192.168.8.250:554/Streaming/Channels/101/");
	play(rtspTcpClientSocket, rtspSockAddr, realm, nonce, response.c_str(), session);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	create_rtp_udp_connect(rtpUdpClientSocket, rtpSockAddr, 23332);//����UDPͨ�ţ�����RTP����
	thread assembleRtpToH264Thread(assembleRtpToH264);//��������̣߳�RTP����Ϊh264�ļ�

	int i = 0;
	while (1)//��ʼ����RTP��Ƶ����
	{
		if (i++ >= RTP_PACK_NUM)
			break;

		recvBuf.len = recvData(rtpUdpClientSocket, recvBuf.rtpPackBuf, false);
		rtpPackList.push_back(recvBuf);//�������
	}

	/* 6.TEARDOWN */
	response = md5ToResponse(string(realm), string(nonce), "TEARDOWN", "rtsp://192.168.8.250:554/Streaming/Channels/101/");
	teardown(rtspTcpClientSocket, rtspSockAddr, realm, nonce, response.c_str(), session);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	closesocket(rtpUdpClientSocket);
	closesocket(rtspTcpClientSocket);

	assembleRtpToH264Thread.join();//�ȴ��߳�ִ�н���
	fclose(fRtpToH264);
#endif

#if H264_TO_RTP
	/* ����H264���ݣ���H264��ΪRTP�����͸�VLC���� */
	fH264ToRtp = fopen(H264_FILENAME, "rb");
	if (NULL == fH264ToRtp)
	{
		cout << "���ļ�ʧ��" << endl;
	}
	create_send_rtp_udp_connect(rtpUdpServerSocket, rtpSockAddr, 23334);
	splitH264ToRtp();//���H264������RTP��

	fclose(fH264ToRtp);
	closesocket(rtpUdpServerSocket);
#endif

	WSACleanup();

	return 0;
}
