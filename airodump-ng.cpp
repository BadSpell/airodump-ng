// BoB 6th Airodump-ng assignment
// code by BadSpell(KJS)
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <map>
#include "custom_structs.h"

using namespace std;
map<unsigned long long, BEACONFRAME_INFO> bfmap;
map<unsigned __int128, PROBERESPONSE_INFO> prmap;
int channel_table[] = { 1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12 };
int adt_ch = 0;

void display_update()
{
	printf("\e[2J\e[H"); //clear all
	printf("\n CH %d]\n\n", channel_table[adt_ch]);
	printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
	for (map<unsigned long long, BEACONFRAME_INFO>::iterator iter = bfmap.begin(); iter != bfmap.end(); iter++)
	{
		if (iter->second.ESSID[0])
		{
			printf(" %s%6d%9d%6d%6d%5d %-6s%-5s%-7s%-5s%s\n", iter->second.BSSID, iter->second.ssiSignal,
				iter->second.beaconCount, iter->second.data, iter->second.s, iter->second.channel,
				iter->second.mb, EncTable[iter->second.enc], ChiperTable[iter->second.cipher], AuthTable[iter->second.auth], iter->second.ESSID);
		}
	}

	printf("\n BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n");
	for (map<unsigned __int128, PROBERESPONSE_INFO>::iterator iter = prmap.begin(); iter != prmap.end(); iter++)
	{
		//unsigned long long key = iter->first & 0xFFFFFFFFFFFFFFFF;

		printf(" %-19s%-20s%3d  %-3s %6d %5d      %-5s\n", iter->second.BSSID, iter->second.station,
			iter->second.ssiSignal, iter->second.rate, iter->second.lost,
			iter->second.frames, iter->second.probe);
	}
}

long long tickCount()
{
    struct timeval te; 
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
    return milliseconds;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	pcap_t *handle;
	const u_char *captured_packet;
	struct pcap_pkthdr *header;
	int pn_result, sockfd;

	if (argc < 2)
	{
		printf("[*] Usage: %s [interface]\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)) == NULL)
	{
		printf("[-] Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("[-] Open Raw socket error.\n");
		return 2;
	}
	long long tick = 0;
	while ((pn_result = pcap_next_ex(handle, &header, &captured_packet)) >= 0)
	{
		if (tickCount() - tick > 250) // Send ARP Spoofing interval 1 second
		{
			tick = tickCount();
			display_update();

			char temp[255];
			snprintf(temp, sizeof(temp), "iwconfig %s channel %d", argv[1], channel_table[adt_ch]);
			system(temp);
			adt_ch = (adt_ch + 1) % (sizeof(channel_table) / sizeof(int));
		}
		if (!pn_result)
			continue;

		LPRADIOTAP_HEADER radioTap = (LPRADIOTAP_HEADER)captured_packet;

		/* For debugging
		static int count = 0;

		count++;
		printf("--------- FRAME NUMBER %d ---------\n", count);
		for (int j = 0; j < 0x30; j += 0x10 )
		{
			for (int i = 0; i < 0x10; i++)
				printf("%02X ", captured_packet[j + i]);
			printf("\n");
		}
		printf("\n");
		if (count != 10)
			continue;
		return 0;
		/**/

		LPIEEE_802_11 ieee = (LPIEEE_802_11)(captured_packet + radioTap->headerLength);

		if (ieee->frameControl_Version)
			continue;

		//if (ieee->Flags)
		//	continue;

		unsigned long long key = 0;
		memcpy(&key, ieee->bssId, 6);
		if (!bfmap.count(key))
			memset(&bfmap[key], 0x00, sizeof(BEACONFRAME_INFO));

		LPIEEE_802_11_WIRELESS_FIXED ieee_wf = (LPIEEE_802_11_WIRELESS_FIXED)((u_char *)ieee + sizeof(IEEE_802_11));
		LPIEEE_802_11_WIRELESS_TAGGED ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wf + sizeof(IEEE_802_11_WIRELESS_FIXED));
		int tagLength = header->caplen - ((unsigned long)captured_packet - (unsigned long)ieee_wt);
	
		if (ieee->frameControl_Type == 2) // data frame
			bfmap[key].data++;

		if (ieee->frameControl_Type == 0 && ieee->frameControl_Subtype == 8) // beacon frame
		{
			BEACONFRAME_INFO beaconframe = bfmap[key];
			bool firstTag = true;
			bool qos = false;
			int max_speed = 0, speed;

			if (ieee_wf->capabilities_Privacy == 0)
			{
				beaconframe.enc = ENCTYPE_OPN;
				beaconframe.cipher = CIPHER_UNKNOWN;
			}
			while (tagLength > 0)
			{
				char SSID[33] = { 0 };
				unsigned char current_channel;
				unsigned char *mode = (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED);
				unsigned short count;

				switch (ieee_wt->tagNumber)
				{
				case 0x00: // ssid
					if (!firstTag || ieee_wt->tagLength > 32) //corrupted check
						break;

					sprintf(beaconframe.BSSID, "%02X:%02X:%02X:%02X:%02X:%02X",
						ieee->bssId[0], ieee->bssId[1], ieee->bssId[2],
						ieee->bssId[3], ieee->bssId[4], ieee->bssId[5]
					);
					if (!beaconframe.getESSID)
					{
						memcpy(SSID, (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED), ieee_wt->tagLength);
						if (!SSID[0])
							sprintf(SSID, "<length: %d>", ieee_wt->tagLength);
						else
							beaconframe.getESSID = true;

						strcpy(beaconframe.ESSID, SSID);
					}
					break;

				case 0x01:
				case 0x02:
					speed = (*(mode + ieee_wt->tagLength - 1) & 0x7F) / 2;
					if (max_speed < speed)
						max_speed = speed;
					break;

				case 0x03: // ds parameter
					current_channel = *(unsigned char *)((u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED));
					beaconframe.channel = current_channel;
					break;

				case 0x30: // rsn information
					beaconframe.enc = ENCTYPE_WPA2;
					try
					{
						mode += 6;
						count = *(unsigned short *)mode;
						mode += 2;
						for (int i = 0; i < count; i++, mode += 4)
						{
							switch (*(mode + 3))
							{
							case 1:
								beaconframe.cipher = CIPHER_WEP;
								break;

							case 2:
								beaconframe.cipher = CIPHER_TKIP;
								break;

							case 3:
								beaconframe.cipher = CIPHER_WARP;
								break;

							case 4:
								beaconframe.cipher = CIPHER_CCMP;
								break;

							case 5:
								beaconframe.cipher = CIPHER_WEP104;
								break;

							default:
								beaconframe.cipher = CIPHER_UNKNOWN;
								break;
							}
						}
						count = *(unsigned short *)mode;
						mode += 2;
						for (int i = 0; i < count; i++, mode += 4)
						{
							switch (*(mode + 3))
							{
							case 1:
								beaconframe.auth = AUTH_MGT;
								break;

							case 2:
								beaconframe.auth = AUTH_PSK;
								break;

							default:
								beaconframe.auth = AUTH_UNKNOWN;
								break;
							}
						}
					}
					catch (int e) { }
					break;

				case 0xDD:
					if (!memcmp(mode, "\x00\x50\xF2\x02\x01\x01", 6))
					{
						qos = true;
						break;
					}
					break;
				}

				firstTag = false;
				tagLength -= (ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
				ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wt + ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
			}

			sprintf(beaconframe.mb, "%3d%s%s", speed, qos ? "e" : "", ieee_wf->capabilities_ShortPreamble ? "." : "");
			beaconframe.beaconCount++;
			if (!radioTap->_reserved1)
				beaconframe.ssiSignal = (char)radioTap->ssiSignal / 2;
			bfmap[key] = beaconframe;
			display_update();
			continue;
		}

		if (ieee->frameControl_Type == 2 && ieee->frameControl_Subtype == 4) // Null function
		{
			unsigned long long key1 = 0, key2 = 0;
			unsigned __int128 key;

			memcpy(&key1, ieee->bssId, 6);
			memcpy(&key2, ieee->sourceAddress, 6);
			key = key1 | ((unsigned __int128)key2 << 64);
			if (!prmap.count(key))
				memset(&prmap[key], 0x00, sizeof(PROBERESPONSE_INFO));

			PROBERESPONSE_INFO proberesponse = prmap[key];
			if (!radioTap->_reserved1)
				proberesponse.ssiSignal = (char)radioTap->ssiSignal / 2;
			strcpy(proberesponse.rate, "0 - 0"); //temp

			sprintf(proberesponse.BSSID, "%02X:%02X:%02X:%02X:%02X:%02X",
				ieee->bssId[0], ieee->bssId[1], ieee->bssId[2],
				ieee->bssId[3], ieee->bssId[4], ieee->bssId[5]
			);
			sprintf(proberesponse.station, "%02X:%02X:%02X:%02X:%02X:%02X",
				ieee->sourceAddress[0], ieee->sourceAddress[1], ieee->sourceAddress[2],
				ieee->sourceAddress[3], ieee->sourceAddress[4], ieee->sourceAddress[5]
			);
			while (tagLength > 0)
			{
				char SSID[33] = { 0 };
				unsigned char current_channel;
				unsigned char *mode = (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED);
				unsigned short count;

				switch (ieee_wt->tagNumber)
				{
				case 0x00: // ssid
					if (!proberesponse.getESSID)
					{
						memcpy(SSID, (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED), ieee_wt->tagLength);
						if (!SSID[0])
							sprintf(SSID, "<length: %d>", ieee_wt->tagLength);
						else
							proberesponse.getESSID = true;

						strcpy(proberesponse.probe, SSID);
					}
					break;

				case 0x01:
					break;
				}
				tagLength -= (ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
				ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wt + ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
			}

			proberesponse.frames++;
			prmap[key] = proberesponse;
			display_update();
			continue;
		}
	}
	pcap_close(handle);
	return 0;
}