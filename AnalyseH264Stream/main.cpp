#include "main.h"

using namespace std;
#pragma comment(lib,"ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS

deque<rtpBuf> rtpPackList;//rtp包队列

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
		printf("tan90° value : %s", value);
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

	//向服务器发出连接请求
	if (connect(sock, (sockaddr*)&sockAddr, sizeof(sockAddr)) == -1) {
		printf("Connect failed:%d", WSAGetLastError());
		return -1;
	}

	return 0;
}

int create_rtp_udp_connect(SOCKET& sock, sockaddr_in& sockAddr, int port)
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);//创建RTP通信的socket
	if (SOCKET_ERROR == sock) {
		printf("Socket() error:%d", WSAGetLastError());
		return -1;
	}

	sockAddr.sin_port = htons(port);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("192.168.8.233");

	if (bind(sock, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) == -1)//绑定本地端口
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
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//创建RTP通信的socket
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

//return: 接收到的数据长度
/*
发送各个方法后成功都会返回状态码200 OK
状态码（Status-Code）是一个三位数的整数，用于描述接收方对所收到请求消息的执行结果，
Status-Code的第一位数字指定了这个回复消息的种类，一共有5类：
 1XX: Informational – 请求被接收到，继续处理
 2XX: Success – 请求被成功的接收，解析并接受
 3XX: Redirection – 为完成请求需要更多的操作
 4XX: Client Error – 请求消息中包含语法错误或是不能够被有效执行
 5XX: Server Error – 服务器响应失败，无法处理正确的有效的请求消息
*/
int recvData(SOCKET& sock, char *recvBuf, bool printFlag)
{
	SOCKADDR_IN sockAddr;
	socklen_t addrLen = sizeof(sockAddr);

	int len = recvfrom(sock, recvBuf, RTP_RECV_DATA_LEN, 0, (SOCKADDR*)&sockAddr, &addrLen);
	if (len > 0)
	{
		if (printFlag)//是否打印
		{
			recvBuf[len] = '\0';
			printf("接收到数据len = %d\n%s\n", len, recvBuf);
		}
	}
	else
	{
		printf("recvfrom Error\n");
	}
	return len;
}

/*
计算认证所需的response参数，采用MD5加密，digest/response 计算方法
	hs1 = md5hash(username + ":" + realm + ":" + password)
	hs2 = md5hash(method + ":" + requestUri)
	response = md5hash(hs1 + ":" + nonce + ":" + hs2)

	username：用户名
	password： 密码
	realm： 通常一个 server 对应一个 realm
	method：请求方法（OPTIONS/DESCRIBE/SETUP/PLAY）
	requestUri： 请求的 uri
	nonce： 随机字符串，通常一个 session 对应一个 nonce
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

//第一次发送describe会返回401提示认证
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

//返回401时需要客户端认证
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
		trackID=1通道
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
		if (rtpPackList.empty() == false)//如果不为空
		{
			buf = rtpPackList.front();//出队对头元素
			rtpPackList.pop_front();//删除队头元素
			//printf("len = %d\n", buf.len);
			//hex_dump(buf.rtpPackBuf, buf.len);

			/* 开始解析RTP数据 */
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
			rtpPack.payload.fu_indicator.type = buf.rtpPackBuf[12] & 0x1f; //表示NALU类型
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
			  		
			rtpPack.payload.data = &(buf.rtpPackBuf[12]);//得到视频数据，包括1字节FU_indicator、1字节FU_header（SEI、SPS、PPS没有FU_header）
			//cout << "视频数据: " << endl;
			//hex_dump(rtpPack.payload.data, buf.len-12); 

			int dataLen = buf.len - 12;//减去12字节RTP头信息长度
			int addLen = 0;//附加位长度
			unsigned char nal;
			if (1 == rtpPack.header.p)//p置位表示有附加位
			{
				addLen = rtpPack.payload.data[dataLen - 1];//得到附加位长度，payload最后一个字节为附加位长度
				dataLen -= addLen;//减去附加位
			}

			if (1 == rtpPack.payload.fu_indicator.type)//P帧
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x61;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //减去1字节FU_indicator，剩余的为SEI数据
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data从1开始，去除FU_indicator数据
			}
			else if (6 == rtpPack.payload.fu_indicator.type)//SEI
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x06;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //减去1字节FU_indicator，剩余的为SEI数据
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data从1开始，去除FU_indicator数据
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
				dataLen -= 1; //减去1字节FU_indicator，剩余的为SPS数据
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data从1开始，去除FU_indicator数据
			}
			else if (8 == rtpPack.payload.fu_indicator.type)//PPS
			{
				h264Flag[0] = 0x00;
				h264Flag[1] = 0x00;
				h264Flag[2] = 0x00;
				h264Flag[3] = 0x01;
				h264Flag[4] = 0x68;
				fwrite(h264Flag, 1, 5, fRtpToH264);
				dataLen -= 1; //减去1字节FU_indicator，剩余的为PPS数据
				fwrite(&rtpPack.payload.data[1], 1, dataLen, fRtpToH264);//payload.data从1开始，去除FU_indicator数据
			}
			else if (24 == rtpPack.payload.fu_indicator.type)//STAP-A
			{
				printf("STAP-A:单一时间的组合包\n");
			}
			else if (25 == rtpPack.payload.fu_indicator.type)//STAP-B
			{
				printf("STAP-B:单一时间的组合包\n");
			}
			else if (26 == rtpPack.payload.fu_indicator.type)//MTAP16
			{
				printf("MTAP16:多个时间的组合包\n");
			}
			else if (27 == rtpPack.payload.fu_indicator.type)//MTAP24
			{
				printf("MTAP24:多个时间的组合包\n");
			}
			else if (28 == rtpPack.payload.fu_indicator.type)//FU_A
			{
				nal = (rtpPack.payload.fu_indicator.f << 7) | (rtpPack.payload.fu_indicator.nri << 5) | rtpPack.payload.fu_header.type;
				dataLen -= 2; //减去1字节FU_indicator和1字节FU_header,剩余的为h264数据
				if (0 == rtpPack.header.m)//maker = 0 分片包，非最后一包
				{
					if (1 == rtpPack.payload.fu_header.s)//s = 1 分片包第一包
					{
						h264Flag[0] = 0x00;
						h264Flag[1] = 0x00;
						h264Flag[2] = 0x00;
						h264Flag[3] = 0x01;
						h264Flag[4] = nal;
						fwrite(h264Flag, 1, 5, fRtpToH264);
						fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data从2开始，去除FU_indicator和FU_header数据
					}
					else//s == 0 && e == 0分片包中间包
					{
						fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data从2开始，去除FU_indicator和FU_header数据
					}
				}
				else//maker = 1 分片包最后一包
				{
					fwrite(&rtpPack.payload.data[2], 1, dataLen, fRtpToH264);//payload.data从2开始，去除FU_indicator和FU_header数据
				}
			}
			else if (29 == rtpPack.payload.fu_indicator.type)//FU_B
			{
				printf("FU_B:分片包B\n");
			}
			else
			{
				printf("This pack is error!\n");
			}

			if ((rtpPack.header.seqNum - i) == 1)
				cout << "rtp.seqNum: " << rtpPack.header.seqNum << endl;
			else
				cout << "当前seqNum与上一包seqNum相差不为1" << endl;
			i = rtpPack.header.seqNum;

			if (count++ >= RTP_PACK_NUM)//处理指定包数
				break;

			memset(buf.rtpPackBuf, 0, sizeof(buf.rtpPackBuf));
		}
	}
}

/* 判断是否为开始码: 00 00 00 01 */
bool isStartCode(unsigned char* buf)
{
	if ((0 == buf[0]) && (0 == buf[1]) && (0 == buf[2]) && (1 == buf[3]))
	{
		return true;
	}
	return false;
}

/* 获取H264的一个NALU单元，以00 00 00 00 01开始，以下一个00 00 00 01结束。buf中不包含起始码（1字节包含NALU头和视频数据） */
int getNALU(unsigned char* buf)
{
	unsigned int pos;//保存文件指针当前偏移值
	unsigned char* naluBuf;

	naluBuf = (unsigned char*)calloc(NALU_BUFFER, sizeof(char));//分配1M空间，存储一帧数据
	if (NULL == naluBuf)
	{
		printf("calloc naluBuff failed!\n");
		return -1;
	}

	int len = fread(naluBuf, 1, 4, fH264ToRtp);//H264文件开始的4个字节应该为00 00 00 01
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
		if (feof(fH264ToRtp))//判断是否到了文件尾
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

		naluBuf[pos++] = fgetc(fH264ToRtp);//从文件指针当前位置读一个字节，文件指针往后偏移一位
		startCodeFlag = isStartCode(&naluBuf[pos - 4]);//检查是否到了下一个起始码
		if (startCodeFlag)
			break;
	}

	if (0 != fseek(fH264ToRtp, -4, SEEK_CUR))//设置文件指针向后偏移4字节（4字节开始码），成功返回0
	{
		printf("set fseek failed!\n");
		free(naluBuf);
		return -1;
	}

	//拷贝一个完整NALU，不拷贝前后的起始码00 00 00 01，当前的naluBuf中包含两组起始码
	int naluDataLen = pos - 8;//两组起始码总长为8
	memcpy(buf, &naluBuf[4], naluDataLen);//naluBuf[4]：略过第一组的起始码

	free(naluBuf);
	return naluDataLen;
}

void splitH264ToRtp()
{
	int ret;
	unsigned int len, timestamp_increase = 0, timestamp = 0;
	unsigned int seq_num = 1;
	unsigned char* naluData;//保存一个NALU单元的数据（不包括起始码00 00 00 01）
	naluData = (unsigned char*)calloc(NALU_BUFFER, sizeof(char));//分配1M空间，存储一帧数据
	if (NULL == naluData)
	{
		printf("calloc naluData failed!\n");
		return;
	}

	timestamp_increase = (unsigned int)(90000.0 / FRAMERATE);

	while (!feof(fH264ToRtp))//每次循环发送一个起始码到下一个起始码的数据
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
		rtp_header = (RTP_FIXED_HEADER*)&sendBuf.rtpPackBuf[0];//将sendBuf中的前12字节强转为RTP的12字节固定头
		rtp_header->v = 2;
		rtp_header->p = 0;
		rtp_header->x = 0;
		rtp_header->cc = 0;
		rtp_header->m = 0;
		rtp_header->pt = H264;
		rtp_header->ssrc = htonl(12345678);//随机指定

		if ((7 == nalu.type) || (1 == nalu.type))//设置时间戳，SPS、PPS、SEI和I帧需相同
		{
			timestamp += timestamp_increase;
			rtp_header->timestamp = htonl(timestamp);
		}

		printf("nalu.type : %x, timestamp : %u, data[0] : %2X, len : %u\n", nalu.type, timestamp, naluData[0], len);
		if (len <= 1400)//单包发送
		{
			if ((6 != nalu.type) && (7 != nalu.type) && (8 != nalu.type))//SPS、PPS、SEI的marker不标记为一帧的结束
			{
				rtp_header->m = 1;
			}
			rtp_header->seqNum = htons(seq_num++);//htons htonl将主机字节序转成网络字节序（大端模式）,否则字节倒序排列

			sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | nalu.type;//单包的FU_indicator
			memcpy(&sendBuf.rtpPackBuf[13], &naluData[1], len-1);//naluData[1]去掉NALU头
			sendBuf.len = 12 + len;
			ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
			//if (ret != SOCKET_ERROR)
			//	cout << "单包发送成功 : " << ret << endl;
			//else
			//	cout << "单包发送失败" << endl;
		}
		else if (len > 1400)//FU_A分包
		{
			int count, lastLen, nowCount = 0;//lastLen保存末尾包剩余的长度，nowCount保存当前发送的包
			count = len / 1400;//计算有多少个包
			lastLen = len % 1400;//最后一包数据的字节长度

			while (nowCount <= count)
			{
				rtp_header->seqNum = htons(seq_num++);
				if (0 == nowCount)//分片包的第一包
				{
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (1 << 7) | (0 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[1], 1400-1);//naluData[1]去掉NALU头
					sendBuf.len = 14 + 1400 - 1;//12RTP头+FU_indicator+FU_Header+1400-NALU头
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "第一包发送成功 : " << ret << endl;
					//else
					//	cout << "第一包发送失败" << endl;

				}
				else if (nowCount == count)//最后一包
				{
					rtp_header->m = 1;
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (0 << 7) | (1 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[nowCount*1400], lastLen);
					sendBuf.len = 14 + lastLen;//12RTP头+FU_indicator+FU_Header+lastLen
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "最后一包发送成功 : " << ret << endl;
					//else
					//	cout << "最后一包发送失败" << endl;
				}
				else//中间包
				{
					sendBuf.rtpPackBuf[12] = (nalu.f << 7) | (nalu.nri << 5) | 28;//FU_indicator:F NRI Type
					sendBuf.rtpPackBuf[13] = (0 << 7) | (0 << 6) | (0 << 5) | nalu.type;//FU_Header:S E R Type
					memcpy(&sendBuf.rtpPackBuf[14], &naluData[nowCount*1400], 1400);
					sendBuf.len = 14 + 1400;//12RTP头+FU_indicator+FU_Header+1400
					ret = sendto(rtpUdpServerSocket, sendBuf.rtpPackBuf, sendBuf.len, 0, (SOCKADDR*)&rtpSockAddr, sizeof(rtpSockAddr));
					//if (ret != SOCKET_ERROR)
					//	cout << "中间包发送成功 : " << ret << endl;
					//else
					//	cout << "中间包发送失败" << endl;

				}
				cout << sendBuf.len << " ";
				nowCount++;
			}
			cout << endl;
		}
		_sleep(50);//发完一帧延时，防止过快发送完
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
		printf("初始化失败!");
		return -1;
	}

#if RTP_TO_H264
	/* 接收来自网络摄像头的RTP数据，先创建TCPSocket进行RTSP通信，再创建UDPSocket接收RTP数据，然后解析RTP数据并存入文件 */
	fRtpToH264 = fopen(H264_FILENAME, "wb+");//必须以二进制的方式打开文件，以文本方式打开会自动添加0x0d('\n')，导致播放花屏
	if (NULL == fRtpToH264)
	{
		cout << "打开文件失败" << endl;
	}

	create_rtsp_tcp_connect(rtspTcpClientSocket, rtspSockAddr, RTSP_CLIENT_PORT);

	/* 1.OPTIONS */
	options(rtspTcpClientSocket, rtspSockAddr);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 2.DESCRIBE */
	describe(rtspTcpClientSocket, rtspSockAddr);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	/* 3.DESCRIBE认证 */
	char realm[32], nonce[64];//获取realm和nonce
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

	create_rtp_udp_connect(rtpUdpClientSocket, rtpSockAddr, 23332);//创建UDP通信，接收RTP数据
	thread assembleRtpToH264Thread(assembleRtpToH264);//创建组包线程，RTP包组为h264文件

	int i = 0;
	while (1)//开始接收RTP视频数据
	{
		if (i++ >= RTP_PACK_NUM)
			break;

		recvBuf.len = recvData(rtpUdpClientSocket, recvBuf.rtpPackBuf, false);
		rtpPackList.push_back(recvBuf);//数据入队
	}

	/* 6.TEARDOWN */
	response = md5ToResponse(string(realm), string(nonce), "TEARDOWN", "rtsp://192.168.8.250:554/Streaming/Channels/101/");
	teardown(rtspTcpClientSocket, rtspSockAddr, realm, nonce, response.c_str(), session);
	recvBuf.len = recvData(rtspTcpClientSocket, recvBuf.rtpPackBuf, true);

	closesocket(rtpUdpClientSocket);
	closesocket(rtspTcpClientSocket);

	assembleRtpToH264Thread.join();//等待线程执行结束
	fclose(fRtpToH264);
#endif

#if H264_TO_RTP
	/* 发送H264数据，把H264分为RTP包发送给VLC播放 */
	fH264ToRtp = fopen(H264_FILENAME, "rb");
	if (NULL == fH264ToRtp)
	{
		cout << "打开文件失败" << endl;
	}
	create_send_rtp_udp_connect(rtpUdpServerSocket, rtpSockAddr, 23334);
	splitH264ToRtp();//拆分H264并发送RTP包

	fclose(fH264ToRtp);
	closesocket(rtpUdpServerSocket);
#endif

	WSACleanup();

	return 0;
}
