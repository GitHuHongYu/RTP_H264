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

#define RTP_RECV_DATA_LEN 1500 //��������С��rtp�������1500
#define RTSP_CLIENT_PORT 554  //rtspͨ��Ŀ�Ķ˿�
#define RTP_PACK_NUM 1000    //����RTP�İ���
#define H264 96             //�غ�����
#define FRAMERATE 12       //֡��
#define NALU_BUFFER 1*1024*1024 //1M�ռ�
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
typedef struct //12�ֽ�RTPͷ
{
	/* byte 0 */
	unsigned char cc : 4;       //bit4: Contributing source identifiers count == 0
	unsigned char x  : 1;       //bit1: extension
	unsigned char p  : 1;       //bit1: padding,�����λ��λ�����RTP����β���Ͱ������ӵ�����ֽ�,���һ���ֽڱ��渽��λ�ĳ���(�������һλ����)
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
FU indicator�����¸�ʽ��
+ ----------------------------- +
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| F |  NRI  |        Type       |
+------------------------------- +
Tyep: �غɽṹ����Ϊ������NAL��Ԫ(1-23)���ۺϰ�(STAP-A��STAP-B��MTAP16��MTAP24=24-27)����Ƭ��Ԫ(FU_A��FU_B = 28��29)
6:������ǿ��Ϣ��Ԫ SEI
7:���в����� SPS
8:ͼ������� PPS
*/
typedef struct
{
	unsigned char type : 5;
	unsigned char nri : 2;
	unsigned char f : 1;
}FU_INDICATOR;

/*
FU header�ĸ�ʽ���£�
+ ----------------------------- +
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| S | E | R |        Type       |
+------------------------------ +
��һ��:	 S=1,E=0;
�м��:  S=0,E=0
����:  S=0,E=1
Type: 
	5ΪI֡��1ΪP֡
*/
typedef struct
{
	unsigned char type : 5;//NAI Type��I֡Ϊ5��
	unsigned char r : 1;//��������Ϊ0
	unsigned char e : 1;//Ϊ1��ʾ��Ƭ������
	unsigned char s : 1;//Ϊ1��ʾ��Ƭ����ʼ
}FU_HEADER;

/*
H264��NALUͷ��һ���ֽ����
+---------------+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |
+---------------+
F and NIR ���� FU_INDICATOR���F and NIR
Type ���� FU_HEADER���Type
*/
typedef struct
{
	unsigned char type : 5;
	unsigned char nri : 2;
	unsigned char f : 1;
}NALU_HEADER;

/*
	ȡFU_indicator��ǰ��λ��FU_Header�ĺ���λ�����NAL����65��ʾI֡��

	h264������֡ͷ����:
	00 00 00 01 67 (SPS)
	00 00 00 01 68 (PPS)
	00 00 00 00 06 (SEI)
	00 00 00 01 65 (IDR֡)
	00 00 00 01 61 (P֡)
*/
typedef struct
{
	FU_INDICATOR fu_indicator;
	FU_HEADER fu_header;
	char *data; //��Ƶ����
}RTP_PAYLOAD;

typedef struct
{
	RTP_FIXED_HEADER header;
	RTP_PAYLOAD payload;
}RTP_PACK;

typedef struct
{
	char rtpPackBuf[RTP_RECV_DATA_LEN];//���汣��һ��RTP����,����RTPͷ��Payload
	int len;//ʵ�����ݳ���
}rtpBuf;

RTP_PACK rtpPack;

RTP_FIXED_HEADER* rtp_header;

NALU_HEADER nalu;

rtpBuf recvBuf;//����RTP����
rtpBuf sendBuf;//����RTP����

FILE* fRtpToH264 = NULL;
FILE* fH264ToRtp = NULL;

SOCKET rtpUdpClientSocket; //rtpͨ��udp Socket
SOCKET rtspTcpClientSocket;//rtspͨ��tcp socket
SOCKET rtpUdpServerSocket; //��VLC����h264����
SOCKADDR_IN rtspSockAddr;
SOCKADDR_IN rtpSockAddr;

#endif
