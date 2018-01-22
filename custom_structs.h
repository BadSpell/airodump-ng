// custom structs for airodump-ng headers
// code by BadSpell(KJS)
#ifndef __CUSTOM_STRUCTS_H__
#define CUSTOM_STRUCTS_H

typedef struct _RADIOTAP_HEADER
{
	u_int8_t headerRevision;
	u_int8_t headerPad;
	u_int16_t headerLength;
	u_int32_t presentFlags[2];
	u_int8_t flags;
	u_int8_t dataRate;
	u_int16_t channelFrequency;
	u_int16_t channelFlags;
	u_int8_t ssiSignal;
	u_int8_t rxFlags;
	u_int8_t ssiSignal2;
	u_int8_t antenna;
} __attribute__((packed)) RADIOTAP_HEADER, *LPRADIOTAP_HEADER;

typedef struct _IEEE_802_11
{
	u_int8_t frameControl_Version:2;
	u_int8_t frameControl_Type:2;
	u_int8_t frameControl_Subtype:4;
	u_int8_t Flags;
	/*
	u_int8_t Flags_DS_status:2;
	u_int8_t Flags_More_Fragments:1;
	u_int8_t Flags_Retry:1;
	u_int8_t Flags_PWR_MGT:1;
	u_int8_t Flags_More_Data:1;
	u_int8_t Flags_ProtectedFlag:1;
	u_int8_t Flags_OrderFlag:1;
	*/
	u_int16_t duration;
	u_int8_t destinationAddress[6];
	u_int8_t sourceAddress[6];
	u_int8_t bssId[6];
	u_int16_t fragmentNumber:4;
	u_int16_t sequenceNumber:12;
} __attribute__((packed)) IEEE_802_11, *LPIEEE_802_11;

typedef struct _IEEE_802_11_WIRELESS_FIXED
{
	u_int64_t timestamp;
	u_int16_t beaconInterval;
	u_int16_t capabilities_ESS:1;
	u_int16_t capabilities_IBSS:1;
	u_int16_t capabilities_CFP:2;
	u_int16_t capabilities_Privacy:1;
	u_int16_t capabilities_ShortPreamble:1;
	u_int16_t capabilities_PBCC:1;
	u_int16_t capabilities_ChannelAgility:1;
	u_int16_t capabilities_SpectrumManagement:1;
	u_int16_t capabilities_ShortSlotTime:1;
	u_int16_t capabilities_APSD:1;
	u_int16_t capabilities_RadioMeasurement:1;
	u_int16_t capabilities_DSSS_OFDM:1;
	u_int16_t capabilities_DBA:1;
} __attribute__((packed)) IEEE_802_11_WIRELESS_FIXED, *LPIEEE_802_11_WIRELESS_FIXED;

typedef struct _IEEE_802_11_WIRELESS_TAGGED
{
	u_int8_t tagNumber;
	u_int8_t tagLength;
} __attribute__((packed)) IEEE_802_11_WIRELESS_TAGGED, *LPIEEE_802_11_WIRELESS_TAGGED;

typedef struct _BEACONFRAME_INFO
{
	int beaconCount;
	int data;
	int s;
	char BSSID[19]; //xx:xx:xx:xx:xx:xx
	unsigned char channel;
	char ssiSignal;
	char ESSID[33];
	bool getESSID;
	char mb[16];
	char enc[16];
	char cipher[16];
	char auth[16];
} BEACONFRAME_INFO, *LPBEACONFRAME_INFO;

//iter->second.BSSID, iter->second.station,
//			iter->second.ssiSignal, iter->second.rate, iter->lost,
//			iter->second.frames, iter->second.probe
typedef struct _PROBERESPONSE_INFO
{
	char BSSID[19];
	bool getESSID;
	char station[19];
	char ssiSignal;
	char rate[16];
	int lost;
	int frames;
	char probe[33];
} PROBERESPONSE_INFO, *LPPROBERESPONSE_INFO;


#endif