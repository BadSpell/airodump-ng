// BoB 6th Airodump-ng assignment
// code by BadSpell(KJS)
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <map>
#include "custom_structs.h"

using namespace std;
map<unsigned long long, BEACONFRAME_INFO> bfmap;
map<unsigned long long, PROBERESPONSE_INFO> prmap;

void display_update()
{
	printf("\e[2J\e[H"); //clear all
	printf("\n BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
	for (map<unsigned long long, BEACONFRAME_INFO>::iterator iter = bfmap.begin(); iter != bfmap.end(); iter++)
	{
		printf(" %s%6d%9d%6d%6d%5d %-6s%-5s%-7s%-5s%s\n", iter->second.BSSID, iter->second.ssiSignal,
			iter->second.beaconCount, iter->second.data, iter->second.s, iter->second.channel,
			iter->second.mb, iter->second.enc, iter->second.cipher, iter->second.auth, iter->second.ESSID);
	}

	printf("\n\n BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n\n");
	for (map<unsigned long long, PROBERESPONSE_INFO>::iterator iter = prmap.begin(); iter != prmap.end(); iter++)
	{
		printf(" %-19s%-20s%3d  %-3s %6d %5d      %-5s\n", iter->second.BSSID, iter->second.station,
			iter->second.ssiSignal, iter->second.rate, iter->second.lost,
			iter->second.frames, iter->second.probe);
	}
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
	if ((handle = pcap_open_live(dev, BUFSIZ, 1, 200, errbuf)) == NULL)
	{
		printf("[-] Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("[-] Open Raw socket error.\n");
		return 2;
	}
	while ((pn_result = pcap_next_ex(handle, &header, &captured_packet)) >= 0)
	{
		if (!pn_result)
			continue;

		LPRADIOTAP_HEADER radioTap = (LPRADIOTAP_HEADER)captured_packet;

		// radiotap length maybe... windows=15, linux=24
		LPIEEE_802_11 ieee = (LPIEEE_802_11)(captured_packet + radioTap->headerLength);

		if (ieee->frameControl_Version || ieee->frameControl_Type)
			continue;

		if (ieee->Flags)
			continue;

		unsigned long long key = 0;

		memcpy(&key, ieee->bssId, 6);
		LPIEEE_802_11_WIRELESS_FIXED ieee_wf = (LPIEEE_802_11_WIRELESS_FIXED)((u_char *)ieee + sizeof(IEEE_802_11));
		LPIEEE_802_11_WIRELESS_TAGGED ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wf + sizeof(IEEE_802_11_WIRELESS_FIXED));
		int tagLength = header->caplen - ((unsigned long)captured_packet - (unsigned long)ieee_wt);
	
		if (ieee->frameControl_Subtype == 8) // beacon frame
		{
			BEACONFRAME_INFO beaconframe = { 0 };
			bool firstTag = true;
			bool corrupted = false;
			bool qos = false;
			int max_speed = 0, speed;

			beaconframe.ssiSignal = radioTap->ssiSignal;
			if (ieee_wf->capabilities_Privacy == 0)
			{
				strcpy(beaconframe.enc, "OPN");
				strcpy(beaconframe.cipher, "");
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
					if (!firstTag || ieee_wt->tagLength > 32) //corrupted tag
					{
						corrupted = true;
						break;
					}
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
					strcpy(beaconframe.enc, "WPA2");
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
								strcpy(beaconframe.cipher, "WEP");
								break;

							case 2:
								strcpy(beaconframe.cipher, "TKIP");
								break;

							case 3:
								strcpy(beaconframe.cipher, "WARP");
								break;

							case 4:
								strcpy(beaconframe.cipher, "CCMP");
								break;

							case 5:
								strcpy(beaconframe.cipher, "WEP104");
								break;

							default:
								strcpy(beaconframe.cipher, "");
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
								strcpy(beaconframe.auth, "MGT");
								break;

							case 2:
								strcpy(beaconframe.auth, "PSK");
								break;

							default:
								strcpy(beaconframe.auth, "");
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
					//if (!memcmp(mode, "\x00\x50\xF2\x04", 4))
					//	break;
					break;
				}
				if (corrupted)
					break;

				firstTag = false;
				tagLength -= (ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
				ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wt + ieee_wt->tagLength + sizeof(IEEE_802_11_WIRELESS_TAGGED));
			}
			if (corrupted)
				continue;

			sprintf(beaconframe.mb, "%3d%s%s", speed, qos ? "e" : "", ieee_wf->capabilities_ShortPreamble ? "." : "");
			beaconframe.beaconCount = bfmap[key].beaconCount + 1;
			bfmap[key] = beaconframe;
			display_update();
		}
		else if (ieee->frameControl_Subtype == 5) // probe response
		{
			PROBERESPONSE_INFO proberesponse = { 0 };
			
			proberesponse.ssiSignal = radioTap->ssiSignal;
			strcpy(proberesponse.rate, "0 - 0"); //temp
			while (tagLength > 0)
			{
				char SSID[33] = { 0 };
				unsigned char current_channel;
				unsigned char *mode = (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED);
				unsigned short count;

				switch (ieee_wt->tagNumber)
				{
				case 0x00: // ssid
					sprintf(proberesponse.BSSID, "%02X:%02X:%02X:%02X:%02X:%02X",
						ieee->bssId[0], ieee->bssId[1], ieee->bssId[2],
						ieee->bssId[3], ieee->bssId[4], ieee->bssId[5]
					);
					/*
					sprintf(proberesponse.station, "%02X:%02X:%02X:%02X:%02X:%02X",
						ieee->destinationAddress[0], ieee->destinationAddress[1], ieee->destinationAddress[2],
						ieee->destinationAddress[3], ieee->destinationAddress[4], ieee->destinationAddress[5]
					);
					*/
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

			proberesponse.frames = prmap[key].frames + 1;
			prmap[key] = proberesponse;
			display_update();
		}
	}
	pcap_close(handle);
	return 0;
}