#pragma once
#ifndef _MAIN_H_
#define _MAIN_H_

#include <winsock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <md5.h>
#include <Windows.h>
#include <thread>
#include <deque>
#include <algorithm>

#define RTP_RECV_DATA_LEN 1500 //缓冲区大小，rtp最大数据1500
#define RTSP_CLIENT_PORT 554  //rtsp通信目的端口
#define RTP_PACK_NUM 1000    //处理RTP的包数
#define H264 96             //载荷类型
#define FRAMERATE 12       //帧率
#define NALU_BUFFER 1*1024*1024 //1M空间
#define H264_FILENAME "./test.h264"

/***************************************************************
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*****************************************************************/
typedef struct //12字节RTP头
{
	/* byte 0 */
	unsigned char cc : 4;       //bit4: Contributing source identifiers count == 0
	unsigned char x  : 1;       //bit1: extension
	unsigned char p  : 1;       //bit1: padding,如果该位置位，则该RTP包的尾部就包含附加的填充字节,最后一个字节保存附加位的长度(包括最后一位本身)
	unsigned char v  : 2;       //bit2: version
	/* byte 1 */
	unsigned char pt : 7;       //bit7: payload type
	unsigned char m  : 1;       //bit1: maker
	/* bytes 2, 3 */
	unsigned short seqNum;      //bit16: Sequence number
	/* bytes 4-7 */
	unsigned  int timestamp;    //bit32: Timestamp
	/* bytes 8-11 */
	unsigned int ssrc;          //bit32: Synchronization Source identifier
}RTP_FIXED_HEADER;
/*
FU indicator有以下格式：
+ ----------------------------- +
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| F |  NRI  |        Type       |
+------------------------------- +
Tyep: 载荷结构，分为：单个NAL单元(1-23)、聚合包(STAP-A、STAP-B、MTAP16、MTAP24=24-27)、分片单元(FU_A和FU_B = 28和29)
6:补充增强信息单元 SEI
7:序列参数集 SPS
8:图像参数集 PPS
*/
typedef struct
{
	unsigned char type : 5;
	unsigned char nri : 2;
	unsigned char f : 1;
}FU_INDICATOR;

/*
FU header的格式如下：
+ ----------------------------- +
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| S | E | R |        Type       |
+------------------------------ +
第一包:	 S=1,E=0;
中间包:  S=0,E=0
最后包:  S=0,E=1
Type: 
	5为I帧，1为P帧
*/
typedef struct
{
	unsigned char type : 5;//NAI Type，I帧为5，
	unsigned char r : 1;//保留，总为0
	unsigned char e : 1;//为1表示分片包结束
	unsigned char s : 1;//为1表示分片包开始
}FU_HEADER;

/*
H264的NALU头由一个字节组成
+---------------+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |
+---------------+
F and NIR 等于 FU_INDICATOR里的F and NIR
Type 等于 FU_HEADER里的Type
*/
typedef struct
{
	unsigned char type : 5;
	unsigned char nri : 2;
	unsigned char f : 1;
}NALU_HEADER;

/*
	取FU_indicator的前三位和FU_Header的后五位，组成NAL类型65表示I帧。

	h264常见的帧头数据:
	00 00 00 01 67 (SPS)
	00 00 00 01 68 (PPS)
	00 00 00 00 06 (SEI)
	00 00 00 01 65 (IDR帧)
	00 00 00 01 61 (P帧)
*/
typedef struct
{
	FU_INDICATOR fu_indicator;
	FU_HEADER fu_header;
	char *data; //视频数据
}RTP_PAYLOAD;

typedef struct
{
	RTP_FIXED_HEADER header;
	RTP_PAYLOAD payload;
}RTP_PACK;

typedef struct
{
	char rtpPackBuf[RTP_RECV_DATA_LEN];//保存保存一包RTP数据,包含RTP头和Payload
	int len;//实际数据长度
}rtpBuf;

RTP_PACK rtpPack;

RTP_FIXED_HEADER* rtp_header;

NALU_HEADER nalu;

rtpBuf recvBuf;//接收RTP整包
rtpBuf sendBuf;//发送RTP整包

FILE* fRtpToH264 = NULL;
FILE* fH264ToRtp = NULL;

SOCKET rtpUdpClientSocket; //rtp通信udp Socket
SOCKET rtspTcpClientSocket;//rtsp通信tcp socket
SOCKET rtpUdpServerSocket; //向VLC发送h264数据
SOCKADDR_IN rtspSockAddr;
SOCKADDR_IN rtpSockAddr;

#endif
