

#include <windows.h>
#include <iostream>
#include <gdiplus.h>  // ����ͼ�񱣴棨GDI+��
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>

#include <winternl.h>
#include "zlib.h"
#pragma comment(lib, "gdiplus.lib")
#include <nmmintrin.h>  // ����֧�� POPCNT ָ���ͷ�ļ�

#include <stdio.h>
#include <stdlib.h>

#include <cstdio>
#include <cstring>
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")



#define CpuNum "wmic cpu get DeviceID"
// �����ȡ Cpu �������
#define CpuCoreNum "wmic cpu get NumberOfCores"
// �����ȡ Cpu �߼�����
#define CpuLogicalCoreNum "wmic cpu get NumberOfLogicalProcessors"

#define __AddressWidth "wmic cpu get AddressWidth"
#define __Architecture "wmic cpu get Architecture"
#define __AssetTag "wmic cpu get AssetTag"
#define __Availability "wmic cpu get Availability"
#define __Caption "wmic cpu get Caption"
#define __Characteristics "wmic cpu get Characteristics"
#define __ConfigManagerErrorCode "wmic cpu get ConfigManagerErrorCode"
#define __ConfigManagerUserConfig "wmic cpu get ConfigManagerUserConfig"
#define __CpuStatus "wmic cpu get CpuStatus"
#define __CreationClassName "wmic cpu get CreationClassName"
#define __CurrentClockSpeed "wmic cpu get CurrentClockSpeed"
#define __CurrentVoltage "wmic cpu get CurrentVoltage"
#define __DataWidth "wmic cpu get DataWidth"
#define __Description "wmic cpu get Description"
#define __DeviceID "wmic cpu get DeviceID"
#define __ErrorCleared "wmic cpu get ErrorCleared"
#define __ErrorDescription "wmic cpu get ErrorDescription"
#define __ExtClock "wmic cpu get ExtClock"
#define __Family "wmic cpu get Family"
#define __InstallDate "wmic cpu get InstallDate"
#define __L2CacheSize "wmic cpu get L2CacheSize"
#define __L2CacheSpeed "wmic cpu get L2CacheSpeed"
#define __L3CacheSize "wmic cpu get L3CacheSize"
#define __L3CacheSpeed "wmic cpu get L3CacheSpeed"
#define __LastErrorCode "wmic cpu get LastErrorCode"
#define __Level "wmic cpu get Level"
#define __LoadPercentage "wmic cpu get LoadPercentage"
#define __Manufacturer "wmic cpu get Manufacturer"
#define __MaxClockSpeed "wmic cpu get MaxClockSpeed"
#define __Name "wmic cpu get Name"
#define __NumberOfCores "wmic cpu get NumberOfCores"
#define __NumberOfEnabledCore "wmic cpu get NumberOfEnabledCore"
#define __NumberOfLogicalProcessors "wmic cpu get NumberOfLogicalProcessors"
#define __OtherFamilyDescription "wmic cpu get OtherFamilyDescription"
#define __PartNumber "wmic cpu get PartNumber"
#define __PNPDeviceID "wmic cpu get PNPDeviceID"
#define __PowerManagementCapabilities "wmic cpu get PowerManagementCapabilities"
#define __PowerManagementSupported "wmic cpu get PowerManagementSupported"
#define __ProcessorId "wmic cpu get ProcessorId"
#define __ProcessorType "wmic cpu get ProcessorType"
#define __Revision "wmic cpu get Revision"
#define __Role "wmic cpu get Role"
#define __SecondLevelAddressTranslationExtensions                              \
    "wmic cpu get SecondLevelAddressTranslationExtensions"
#define __SerialNumber "wmic cpu get SerialNumber"
#define __SocketDesignation "wmic cpu get SocketDesignation"
#define __Status "wmic cpu get Status"
#define __StatusInfo "wmic cpu get StatusInfo"
#define __Stepping "wmic cpu get Stepping"
#define __SystemCreationClassName "wmic cpu get SystemCreationClassName"
#define __SystemName "wmic cpu get SystemName"
#define __ThreadCount "wmic cpu get ThreadCount"
#define __UniqueId "wmic cpu get UniqueId"
#define __UpgradeMethod "wmic cpu get UpgradeMethod"
#define __Version "wmic cpu get Version"
#define __VirtualizationFirmwareEnabled                                        \
    "wmic cpu get VirtualizationFirmwareEnabled"
#define __VMMonitorModeExtensions "wmic cpu get VMMonitorModeExtensions"
#define __VoltageCaps "wmic cpu get VoltageCaps"


// ���� RtlGetVersion ��������
typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);
using namespace std;

using namespace Gdiplus;

bool GetEncoderClsid(const WCHAR* pszFormat, CLSID* pClsid);

// ��ʼ�� GDI+�����ڱ���ͼ��
void InitGDIPlus() {
	Gdiplus::GdiplusStartupInput gdiPlusStartupInput;
	ULONG_PTR gdiPlusToken;
	Gdiplus::GdiplusStartup(&gdiPlusToken, &gdiPlusStartupInput, nullptr);
}

// �ر� GDI+
void ShutdownGDIPlus(ULONG_PTR gdiPlusToken) {
	Gdiplus::GdiplusShutdown(gdiPlusToken);
}
// ѹ���ļ�Ϊ Gzip ��ʽ
bool compressGzipFile(const std::string& sourceFilename, const std::string& destFilename) {
	// ��Դ�ļ�
	std::ifstream sourceFile(sourceFilename, std::ios_base::binary);
	if (!sourceFile.is_open()) {
		std::cerr << "Failed to open source file!" << std::endl;
		return false;
	}

	// ��Ŀ���ļ���ѹ����� Gzip �ļ���
	std::ofstream destFile(destFilename, std::ios_base::binary);
	if (!destFile.is_open()) {
		std::cerr << "Failed to open destination file!" << std::endl;
		return false;
	}

	// д Gzip �ļ�ͷ
	unsigned char header[10] = { 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };  // Gzip header
	destFile.write(reinterpret_cast<char*>(header), sizeof(header));

	// ��ʼ�� zlib ѹ����
	z_stream strm = { 0 };
	int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		std::cerr << "deflateInit2 failed!" << std::endl;
		return false;
	}

	// ���û�����
	std::vector<char> buffer(1024); // 1KB ������

	// ѹ��������
	do {
		sourceFile.read(buffer.data(), buffer.size());
		strm.avail_in = static_cast<uInt>(sourceFile.gcount());
		strm.next_in = reinterpret_cast<Bytef*>(buffer.data());

		do {
			strm.avail_out = buffer.size();
			strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
			ret = deflate(&strm, sourceFile.eof() ? Z_FINISH : Z_NO_FLUSH);

			if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
				std::cerr << "Compression failed!" << std::endl;
				deflateEnd(&strm);
				return false;
			}

			unsigned have = buffer.size() - strm.avail_out;
			destFile.write(buffer.data(), have);

		} while (strm.avail_out == 0);

	} while (!sourceFile.eof());

	// ѹ������������
	ret = deflateEnd(&strm);
	if (ret != Z_OK) {
		std::cerr << "deflateEnd failed!" << std::endl;
		return false;
	}

	// д CRC ���ļ���С��Gzip �ļ�β��
	unsigned crc = crc32(0L, Z_NULL, 0);
	unsigned size = static_cast<unsigned>(sourceFile.gcount());
	destFile.write(reinterpret_cast<char*>(&crc), sizeof(crc));
	destFile.write(reinterpret_cast<char*>(&size), sizeof(size));

	return true;
}

// ��λͼ���浽�ڴ�����
void SaveBitmapToMemory(HBITMAP hBitmap, std::vector<BYTE>& imageData, ULONG quality) {
	// ���� GDI+ λͼ����
	Gdiplus::Bitmap bitmap(hBitmap, nullptr);

	// �����ڴ�������
	IStream* pStream = nullptr;
	HRESULT hr = CreateStreamOnHGlobal(nullptr, TRUE, &pStream);
	if (FAILED(hr)) {
		std::cerr << "Failed to create memory stream" << std::endl;
		return;
	}

	// Get the CLSID of the JPEG encoder.
	CLSID encoderClsid;
	if (!GetEncoderClsid(L"image/jpeg", &encoderClsid)) {
		std::cerr << "Failed to  Get the CLSID of the JPEG encoder" << std::endl;
		return;
	}

	// ����ѹ������
	Gdiplus::EncoderParameters encoderParams;
	memset(&encoderParams, 0, sizeof(encoderParams));
	encoderParams.Count = 1;
	Gdiplus::EncoderParameters encoderParameters;
	encoderParameters.Count = 1;
	encoderParameters.Parameter[0].Guid = Gdiplus::EncoderQuality;
	encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
	encoderParameters.Parameter[0].NumberOfValues = 1;
	encoderParameters.Parameter[0].Value = &quality;


	// ����Ϊ�ڴ���
	Gdiplus::Status status = bitmap.Save(pStream, &encoderClsid, &encoderParams);
	if (status != Gdiplus::Ok) {
		std::cerr << "Failed to save bitmap to memory" << std::endl;
		pStream->Release();
		return;
	}

	// ��ȡ�����ݴ�С
	ULARGE_INTEGER liSize;
	hr = pStream->Seek({ 0 }, STREAM_SEEK_END, &liSize);
	if (FAILED(hr)) {
		std::cerr << "Failed to seek to the end of the stream" << std::endl;
		pStream->Release();
		return;
	}

	// ȷ������С��ȷ
	DWORD dwSize = static_cast<DWORD>(liSize.QuadPart);
	imageData.resize(dwSize);

	// �ƶ���ָ�뵽��ʼλ��
	pStream->Seek({ 0 }, STREAM_SEEK_SET, nullptr);

	// ��ȡ�����ݵ� imageData
	ULONG bytesRead;
	hr = pStream->Read(imageData.data(), dwSize, &bytesRead);
	if (FAILED(hr) || bytesRead != dwSize) {
		std::cerr << "Failed to read data from memory stream" << std::endl;
	}

	// ������Դ
	pStream->Release();
}

// ���ڴ��е��ֽ����ݱ��浽�ļ�
void SaveMemoryToFile(const std::vector<BYTE>& imageData, const std::wstring& filename) {
	// ʹ�� std::ofstream ���ļ�����д��
	std::ofstream file(filename, std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file for writing" << std::endl;
		return;
	}

	// ���ڴ��е��ֽ�����д���ļ�
	file.write(reinterpret_cast<const char*>(imageData.data()), imageData.size());
	if (!file) {
		std::cerr << "Failed to write data to file" << std::endl;
	}
	else {
		std::wcout << L"File saved successfully: " << filename << std::endl;
	}

	file.close();
}



bool GetEncoderClsid(const WCHAR* pszFormat, CLSID* pClsid)
{
	UINT  unNum = 0;          // number of image encoders
	UINT  unSize = 0;         // size of the image encoder array in bytes

	Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;

	// How many encoders are there?
	// How big (in bytes) is the array of all ImageCodecInfo objects?
	GetImageEncodersSize(&unNum, &unSize);
	if (0 == unSize) {
		return false;  // Failure
	}

	// Create a buffer large enough to hold the array of ImageCodecInfo
	// objects that will be returned by GetImageEncoders.
	pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(unSize));
	if (!pImageCodecInfo) {
		return false;  // Failure
	}

	// GetImageEncoders creates an array of ImageCodecInfo objects
	// and copies that array into a previously allocated buffer. 
	// The third argument, imageCodecInfos, is a pointer to that buffer. 
	GetImageEncoders(unNum, unSize, pImageCodecInfo);

	for (UINT j = 0; j < unNum; ++j) {
		if (wcscmp(pImageCodecInfo[j].MimeType, pszFormat) == 0) {
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			pImageCodecInfo = NULL;
			return true;  // Success
		}
	}

	free(pImageCodecInfo);
	pImageCodecInfo = NULL;
	return false;  // Failure
}





bool CompressImageQuality(const WCHAR* pszOriFilePath, const WCHAR* pszDestFilePah, ULONG quality)
{

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	Status stat = GenericError;
	stat = GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	if (Ok != stat) {
		return false;
	}

	// ����״̬
	stat = GenericError;

	// Get an image from the disk.
	Image* pImage = new Image(pszOriFilePath);

	do {
		if (NULL == pImage) {
			break;
		}

		// ��ȡ����
		UINT ulHeight = pImage->GetHeight();
		UINT ulWidth = pImage->GetWidth();
		if (ulWidth < 1 || ulHeight < 1) {
			break;
		}

		// Get the CLSID of the JPEG encoder.
		CLSID encoderClsid;
		if (!GetEncoderClsid(L"image/jpeg", &encoderClsid)) {
			break;
		}

		// The one EncoderParameter object has an array of values.
		// In this case, there is only one value (of type ULONG)
		// in the array. We will let this value vary from 0 to 100.
		Gdiplus::EncoderParameters encoderParameters;
		encoderParameters.Count = 1;
		encoderParameters.Parameter[0].Guid = Gdiplus::EncoderQuality;
		encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
		encoderParameters.Parameter[0].NumberOfValues = 1;
		encoderParameters.Parameter[0].Value = &quality;
		stat = pImage->Save(pszDestFilePah, &encoderClsid, &encoderParameters);
	} while (0);

	if (pImage) {
		delete pImage;
		pImage = NULL;
	}

	GdiplusShutdown(gdiplusToken);

	return ((stat == Ok) ? true : false);
}




// ��ȡ���沢����Ϊ�ļ�
void CaptureDesktop(const std::wstring& filename) {
	// ��ȡ��Ļ DC
	HDC hScreenDC = GetDC(nullptr);
	if (hScreenDC == nullptr) {
		std::cerr << "Failed to get screen DC" << std::endl;
		return;
	}

	// ��ȡ��Ļ�ߴ�
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	// �����ڴ� DC
	HDC hMemDC = CreateCompatibleDC(hScreenDC);
	if (hMemDC == nullptr) {
		std::cerr << "Failed to create memory DC" << std::endl;
		ReleaseDC(nullptr, hScreenDC);
		return;
	}

	// ��������Ļ���ݵ�λͼ
	HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
	if (hBitmap == nullptr) {
		std::cerr << "Failed to create bitmap" << std::endl;
		DeleteDC(hMemDC);
		ReleaseDC(nullptr, hScreenDC);
		return;
	}

	// ����Ļ���ݸ��Ƶ��ڴ� DC ��
	SelectObject(hMemDC, hBitmap);
	if (!BitBlt(hMemDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY)) {
		std::cerr << "BitBlt failed" << std::endl;
	}
	else {

		// SaveBitmapToFile(hBitmap, L"desktop_screenshot_compressed.jpg");
		std::vector<BYTE> imageData;
		//// �������沢���浽�ڴ�
		SaveBitmapToMemory(hBitmap, imageData, 30);
		std::wstring filename = L"screenshot_in_memory.jpeg";
		SaveMemoryToFile(imageData, filename);

		// CompressImageQuality(L"desktop_screenshot_compressed.jpg", L"1C.jpg", 30);
	}

	// ������Դ
	DeleteObject(hBitmap);
	DeleteDC(hMemDC);
	ReleaseDC(nullptr, hScreenDC);
}



// ��ѹ Gzip �ļ�
bool decompressGzipFile(const std::string& sourceFilename, const std::string& destFilename) {
	// ��Դ�ļ���Gzip ѹ���ļ���
	std::ifstream sourceFile(sourceFilename, std::ios_base::binary);
	if (!sourceFile.is_open()) {
		std::cerr << "Failed to open source file!" << std::endl;
		return false;
	}

	// ��Ŀ���ļ�
	std::ofstream destFile(destFilename, std::ios_base::binary);
	if (!destFile.is_open()) {
		std::cerr << "Failed to open destination file!" << std::endl;
		return false;
	}

	// ���� Gzip �ļ�ͷ��10 �ֽڣ�
	sourceFile.seekg(10, std::ios::beg);

	// ��ʼ�� zlib ��ѹ��
	z_stream strm = { 0 };
	int ret = inflateInit2(&strm, 16 + MAX_WBITS);  // 16 + MAX_WBITS ��ʾ Gzip ��ʽ
	if (ret != Z_OK) {
		std::cerr << "inflateInit2 failed!" << std::endl;
		return false;
	}

	// ���û�����
	std::vector<char> buffer(1024); // 1KB ������

	// ��ѹ������
	do {
		sourceFile.read(buffer.data(), buffer.size());
		strm.avail_in = static_cast<uInt>(sourceFile.gcount());
		strm.next_in = reinterpret_cast<Bytef*>(buffer.data());

		do {
			strm.avail_out = buffer.size();
			strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
			ret = inflate(&strm, Z_NO_FLUSH);

			if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
				std::cerr << "Decompression failed!" << std::endl;
				inflateEnd(&strm);
				return false;
			}

			unsigned have = buffer.size() - strm.avail_out;
			destFile.write(buffer.data(), have);

		} while (strm.avail_out == 0);

	} while (!sourceFile.eof());

	// ��ѹ����������
	ret = inflateEnd(&strm);
	if (ret != Z_OK) {
		std::cerr << "inflateEnd failed!" << std::endl;
		return false;
	}

	return true;
}

void GetSystemInfoDetails() {
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);


	std::cout << "Processor architecture: ";
	switch (si.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		std::cout << "Intel x86 (32-bit)" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		std::cout << "Intel (x64, 64-bit)" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_ARM:
		std::cout << "ARM (32-bit)" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		std::cout << "Intel Itanium (IA64)" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_MIPS:
		std::cout << "MIPS" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_ALPHA:
		std::cout << "Alpha" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_PPC:
		std::cout << "PowerPC" << std::endl;
		break;
	case PROCESSOR_ARCHITECTURE_SHX:
		std::cout << "SHx" << std::endl;
		break;
	default:
		std::cout << "Unknown architecture" << std::endl;
		break;
	}
	std::cout << "Number of processors: " << si.dwNumberOfProcessors << std::endl;
}

string GetWindowsVersion() {
	// ��ȡ�汾��Ϣ
	RTL_OSVERSIONINFOW osvi;
	ZeroMemory(&osvi, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	// ��ȡ RtlGetVersion ��ַ
	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

	if (RtlGetVersion != nullptr) {
		NTSTATUS status = RtlGetVersion(&osvi);
		if (status == 0) {  // 0 ��ʾ�ɹ�
			std::stringstream versionStream;
			versionStream << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "." << osvi.dwBuildNumber << "." << osvi.dwPlatformId;

			return versionStream.str();
		}
		else {
			std::cerr << "Failed to get version info." << std::endl;
		}
	}
	else {
		std::cerr << "Failed to load RtlGetVersion." << std::endl;
	}
}



// ��ȡ���ڴ��С��MB��
long getTotalMemory() {
	MEMORYSTATUSEX stat;
	stat.dwLength = sizeof(stat);
	GlobalMemoryStatusEx(&stat);
	return stat.ullTotalPhys / (1024 * 1024);  // ת��Ϊ MB
}

// �ֶ�ʵ�� popcount ����
int popcount64(uint64_t value) {
	int count = 0;
	while (value) {
		count += value & 1;  // ������λΪ 1�������
		value >>= 1;          // ���� 1 λ�������һλ
	}
	return count;
}



string GetInstallDate() {
	HKEY hKey;
	DWORD installDate;
	DWORD bufferSize = sizeof(installDate);

	// ��ע����
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS) {

		// ��ȡ InstallDate ��
		if (RegQueryValueExW(hKey, L"InstallDate", nullptr, nullptr, (LPBYTE)&installDate, &bufferSize) == ERROR_SUCCESS) {
			// ע����е�ʱ���Ǵ� 1970 �� 1 �� 1 �տ�ʼ������
			time_t installTime = installDate;

			// ����װʱ��ת��Ϊ�ɶ������ڸ�ʽ
			struct tm timeInfo = { 0 };  // ʹ�� `{0}` ��ʼ���ṹ
			localtime_s(&timeInfo, &installTime);
			char installDateStr[80];
			strftime(installDateStr, sizeof(installDateStr), "%Y-%m-%d %H:%M:%S", &timeInfo);

			return  installDateStr;
		}
		else {
			return "";
		}

		// �ر�ע����
		RegCloseKey(hKey);
	}
	else {
		return "";
	}
}


string GetSystemUptime() {
	// ��ȡϵͳ�������ʱ�䣬��λ�Ǻ���
	DWORD64 uptime = GetTickCount64();

	// ����ϵͳ����ʱ�䣨ת��ΪСʱ�����ӡ��룩
	DWORD64 seconds = uptime / 1000;
	DWORD64 minutes = seconds / 60;
	DWORD64 hours = minutes / 60;
	DWORD64 days = hours / 24;
	stringstream oss;
	oss << days << "d" << hours % 24 << "h"
		<< minutes % 60 << "m" << seconds % 60 << "s";
	return oss.str();
}


// ��ʼ�� COM ��
void InitializeCOM() {
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		cout << "Failed to initialize COM library. Exiting..." << endl;
		exit(1);
	}
}

// ��ȡ�����豸��Ϣ
void GetNetworkAdapters() {
	InitializeCOM();
	// ���� COM ���ӵ� WMI
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;

	HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres)) {
		cout << "Failed to create IWbemLocator object. Exiting..." << endl;
		CoUninitialize();
		exit(1);
	}

	// ���ӵ� WMI �����ռ�
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
	if (FAILED(hres)) {
		cout << "Failed to connect to WMI. Exiting..." << endl;
		pLoc->Release();
		CoUninitialize();
		exit(1);
	}

	// ���� WMI ��ѯ�İ�ȫ��
	hres = CoSetProxyBlanket(
		pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres)) {
		cout << "Failed to set proxy blanket. Exiting..." << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		exit(1);
	}

	// ��ѯ�������������ã�Win32_NetworkAdapterConfiguration��
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_NetworkAdapter"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
		cout << "Failed to query WMI. Exiting..." << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		exit(1);
	}

	// ��ȡ��ѯ���
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator) {
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;

		VARIANT vtProp;
		// ��ȡ��������
		hres = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);
		if (FAILED(hres)) {
			cout << "Failed to get Description." << endl;
		}
		else {
			wcout << L"Network Adapter: " << vtProp.bstrVal << endl;
		}
		VariantClear(&vtProp);
		VARIANT vtProp2;
		// ��ȡ MAC ��ַ
		hres = pclsObj->Get(L"MACAddress", 0, &vtProp2, 0, 0);
		if (FAILED(hres)) {
			cout << "Failed to get MACAddress." << endl;
		}
		else {
			// ��� vtProp �Ƿ�Ϊ��
			if (vtProp2.vt == VT_EMPTY || vtProp2.vt == VT_NULL) {
				continue;
			}
			wcout << L"MAC Address: " << vtProp2.bstrVal << endl;
		}
		VariantClear(&vtProp2);

		pclsObj->Release();
	}

	// ����
	pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();
}




// ��ȡ CPU ��Ϣ
string GetCPUInfo() {
	InitializeCOM();
	// ���� COM ���ӵ� WMI
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;

	HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres)) {
	
		CoUninitialize();
		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// ���ӵ� WMI �����ռ�
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
	if (FAILED(hres)) {
	
		pLoc->Release();
		CoUninitialize();
		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// ���� WMI ��ѯ�İ�ȫ��
	hres = CoSetProxyBlanket(
		pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres)) {
	
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// ��ѯ CPU ��Ϣ
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
	
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// ��ȡ��ѯ���
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	int NumberOfCores = 0;
	int NumberOfLogicalProcessors = 0;
	string cpuNameText = "";
	string deviceIdText = "";
	string result = "";
	while (pEnumerator) {
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;

		VARIANT vtProp;

		hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hres)) {
			std::wstring wideStr(vtProp.bstrVal);
			int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string cpuName(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &cpuName[0], size_needed, nullptr, nullptr);
			cpuNameText = cpuName;

		}
		VariantClear(&vtProp);

		hres = pclsObj->Get(L"DeviceId", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hres)) {
			std::wstring wideStr(vtProp.bstrVal);
			int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string deviceId(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &deviceId[0], size_needed, nullptr, nullptr);
			deviceIdText = deviceId;
		}
		VariantClear(&vtProp);
		string NumberOfCoresText = "";
		// ��ȡ���������
		hres = pclsObj->Get(L"NumberOfCores", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hres)) {
			if (vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL) {
				continue;
			}
			NumberOfCores = NumberOfCores + vtProp.intVal;
			NumberOfCoresText = "<PNC>" + std::to_string(vtProp.intVal) + "</PNC>";

		}
		else {
			NumberOfCoresText = "<PNC>0</PNC>";
		}
		VariantClear(&vtProp);
		string NumberOfLogicalProcessorsText = "";
		// ��ȡ�߼�������
		hres = pclsObj->Get(L"NumberOfLogicalProcessors", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hres)) {
			if (vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL) {
				continue;
			}
			NumberOfLogicalProcessors = NumberOfLogicalProcessors + vtProp.intVal;
			NumberOfLogicalProcessorsText = "<PNLP>" + std::to_string(vtProp.intVal) + "</PNLP>";
		}
		else {
			NumberOfLogicalProcessorsText = "<PNLP>0</PNLP>";
		}
		
		VariantClear(&vtProp);
		result = result + "<PDID>" + deviceIdText + "</PDID><PN>" + cpuNameText + "</PN>"+ NumberOfCoresText+ NumberOfLogicalProcessorsText+"\r\n";
		pclsObj->Release();

	}

	// ����
	pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();
	return "[SYS]<CSNP>" + std::to_string(NumberOfCores) + "</CSNP><CSNLP>" + std::to_string(NumberOfLogicalProcessors) + "</CSNLP>[/SYS]\r\n[CPU]"+ result+"[/CPU]";
}

void report() {
	string systemInfo = "[SystemInfo]\r\n";
	//[NT]10.0.19045.5607[/NT]
	string windowVersion = GetWindowsVersion();
	systemInfo.append("[" + windowVersion + "]\r\n");
	//[SYS]<CSMf>HASEE Computer</CSMf><CSM>CNH5S</CSM><CSTPM>16948453376</CSTPM><CSNP>1</CSNP><CSNLP>16</CSNLP>
	string sysProcessor = "";
	string processorCoresInfoText =  GetCPUInfo();
	sysProcessor = sysProcessor + processorCoresInfoText;
	systemInfo.append(sysProcessor);
	//[UPTimeTick]750484[/UPTimeTick]
	//[UPTime] 0d0h12m30s[/ UPTime]
	string systemUpTimeText =  "\r\n[UPTime]"+GetSystemUptime()+"[/UPTime]";
	string systemInstallDateText =  "\r\n[OSInstallDate]" +  GetInstallDate() + "[/OSInstallDate]";
	systemInfo.append(systemUpTimeText + systemInstallDateText);



	std::cout << systemInfo << std::endl;
	return;

	GetNetworkAdapters();


	return;
	long totalMemory = getTotalMemory();

	std::cout << "Total Memory: " << totalMemory << " MB" << std::endl;

	GetSystemInfoDetails();
	return;
	InitGDIPlus();
	//��ͼ����
	CaptureDesktop(L"screenshot.bmp");
	//

	ShutdownGDIPlus(0);

}