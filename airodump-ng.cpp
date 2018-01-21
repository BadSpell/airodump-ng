// BoB 6th Airodump-ng assignment
// code by BadSpell(KJS)
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <map>
#include "custom_structs.h"

using namespace std;
map<unsigned long long, AIRODUMP_INFO> airomap;

void display_update()
{
	printf("\e[2J\e[H"); //clear all
	printf("\n BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
	
	map<unsigned long long, AIRODUMP_INFO>::iterator iter;
	for (iter = airomap.begin(); iter != airomap.end(); iter++)
	{
		printf(" %s%6d%9d%6d%6d%5d %-6s%-5s%-7s%-5s%s\n", iter->second.BSSID, iter->second.ssiSignal,
			iter->second.beaconCount, iter->second.data, iter->second.s, iter->second.channel,
			iter->second.mb, iter->second.enc, iter->second.cipher, iter->second.auth, iter->second.ESSID);
	}

	printf("\n\n BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n\n");
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

		if (ieee->frameControl_Subtype == 8) // beacon frame
		{
			unsigned long long key = 0;

			memcpy(&key, ieee->bssId, 6);
			if (!key || key == 0xFFFFFFFFFFFF)
				continue;

			LPIEEE_802_11_WIRELESS_FIXED ieee_wf = (LPIEEE_802_11_WIRELESS_FIXED)((u_char *)ieee + sizeof(IEEE_802_11));
			LPIEEE_802_11_WIRELESS_TAGGED ieee_wt = (LPIEEE_802_11_WIRELESS_TAGGED)((u_char *)ieee_wf + sizeof(IEEE_802_11_WIRELESS_FIXED));
			AIRODUMP_INFO airodump = { 0 };
			airodump.ssiSignal = radioTap->ssiSignal;

			int tagLength = header->caplen - ((unsigned long)captured_packet - (unsigned long)ieee_wt);
			bool firstTag = true;
			bool corrupted = false;
			bool qos = false;
			int max_speed = 0, speed;

			if (ieee_wf->capabilities_Privacy == 0)
			{
				strcpy(airodump.enc, "OPN");
				strcpy(airodump.cipher, "");
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
						//corrupted = true;
						//break;
					}
					sprintf(airodump.BSSID, "%02X:%02X:%02X:%02X:%02X:%02X",
						ieee->bssId[0], ieee->bssId[1], ieee->bssId[2],
						ieee->bssId[3], ieee->bssId[4], ieee->bssId[5]
					);
					if (!airodump.getESSID)
					{
						memcpy(SSID, (u_char *)ieee_wt + sizeof(IEEE_802_11_WIRELESS_TAGGED), ieee_wt->tagLength);
						if (!SSID[0])
							sprintf(SSID, "<length: %d>", ieee_wt->tagLength);
						else
							airodump.getESSID = true;

						strcpy(airodump.ESSID, SSID);
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
					airodump.channel = current_channel;
					break;

				case 0x30: // rsn information
					strcpy(airodump.enc, "WPA2");
					mode += 6;
					count = *(unsigned short *)mode;
					mode += 2;
					for (int i = 0; i < count; i++, mode += 4)
					{
						switch (*(mode + 3))
						{
						case 1:
							strcpy(airodump.cipher, "WEP");
							break;

						case 2:
							strcpy(airodump.cipher, "TKIP");
							break;

						case 3:
							strcpy(airodump.cipher, "WARP");
							break;

						case 4:
							strcpy(airodump.cipher, "CCMP");
							break;

						case 5:
							strcpy(airodump.cipher, "WEP104");
							break;

						default:
							strcpy(airodump.cipher, "");
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
							strcpy(airodump.auth, "MGT");
							break;

						case 2:
							strcpy(airodump.auth, "PSK");
							break;

						default:
							strcpy(airodump.auth, "");
							break;
						}
					}
					break;

				case 0xDD:
					if (!memcmp(mode, "\x00\x50\xF2\x02\x01\x01", 6))
					{
						qos = true;
						break;
					}
					if (!memcmp(mode, "\x00\x50\xF2\x04", 4))
					{
						break;
					}
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

			sprintf(airodump.mb, "%3d%s%s", speed, qos ? "e" : "", ieee_wf->capabilities_ShortPreamble ? "." : "");
			airodump.beaconCount = airomap[key].beaconCount + 1;
			airomap[key] = airodump;
			display_update();
		}
	}
	pcap_close(handle);
	return 0;
}