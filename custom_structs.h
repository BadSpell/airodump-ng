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
	u_int32_t _reserved1;
	u_int64_t macTimestamp;
	u_int8_t flags;
	u_int8_t dataRate;
	u_int16_t channelFrequency;
	u_int16_t channelFlags;
	u_int8_t ssiSignal;
	u_int8_t _reserved2;
	u_int16_t rxFlags;
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

const char *EncTable[] = { "", "OPN", "WPA2" };
#define ENCTYPE_UNKNOWN		0
#define ENCTYPE_OPN			1
#define ENCTYPE_WPA2		2

const char *ChiperTable[] = { "", "WEP", "TKIP", "WARP", "CCMP", "WEP104" };
#define CIPHER_UNKNOWN		0
#define CIPHER_WEP			1
#define CIPHER_TKIP			2
#define CIPHER_WARP			3
#define CIPHER_CCMP			4
#define CIPHER_WEP104		5


const char *AuthTable[] = { "", "MGT", "PSK" };
#define AUTH_UNKNOWN		0
#define AUTH_MGT			1
#define AUTH_PSK			2


typedef struct _BEACONFRAME_INFO
{
	int beaconCount;
	int data;
	int s;
	char BSSID[19]; //xx:xx:xx:xx:xx:xx
	u_int8_t channel;
	int8_t ssiSignal;
	char ESSID[33];
	bool getESSID;
	char mb[16];
	int enc;
	int cipher;
	int auth;

	//char enc[16];
	//char cipher[16];
	//char auth[16];
} BEACONFRAME_INFO, *LPBEACONFRAME_INFO;

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