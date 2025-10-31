

#include "report.h"


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


// ��ȡ uint8/uint16 �ı���
static ULONG GetULongProp(IWbemClassObject* obj, LPCWSTR name, ULONG defVal = 0) {
	VARIANT vt; VariantInit(&vt);
	ULONG v = defVal;
	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr))) {
		if (vt.vt == VT_UI1) v = vt.bVal;            // WeekOfManufacture��byte��
		else if (vt.vt == VT_UI2) v = vt.uiVal;      // YearOfManufacture��uint16��
		else if (vt.vt == VT_I4) v = (ULONG)vt.lVal; // ����ĳЩʵ��
		else if (vt.vt == VT_BSTR && vt.bstrVal) v = (ULONG)_wtol(vt.bstrVal);
	}
	VariantClear(&vt);
	return v;
}





// ��ӡ UINT16 ����Ϊ���ո�ָ���ʮ���ơ���ʾ����83 71 84 0 ...
static std::wstring GetUInt16ArrayStrProp(IWbemClassObject* obj, LPCWSTR name) {
	VARIANT vt; VariantInit(&vt);
	std::wstring result;

	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr)) &&
		(vt.vt & VT_ARRAY) && (vt.vt & VT_UI2) && vt.parray) {
		SAFEARRAY* sa = vt.parray;
		LONG l = 0, u = -1;
		SafeArrayGetLBound(sa, 1, &l);
		SafeArrayGetUBound(sa, 1, &u);
		for (LONG i = l; i <= u; ++i) {
			USHORT val = 0;
			if (SUCCEEDED(SafeArrayGetElement(sa, &i, &val))) {
				if (!result.empty()) result += L" ";
				result += std::to_wstring(val);
			}
		}

		return result;
	}
	VariantClear(&vt);
	return L"";
}



static bool SafeArrayToBytes(VARIANT& vt, std::vector<uint8_t>& out) {
	if (!((vt.vt & VT_ARRAY) && (vt.vt & VT_UI1)) || !vt.parray) return false;
	SAFEARRAY* sa = vt.parray;
	LONG l = 0, u = -1;
	if (FAILED(SafeArrayGetLBound(sa, 1, &l)) || FAILED(SafeArrayGetUBound(sa, 1, &u)) || u < l) return false;
	out.resize(size_t(u - l + 1));
	for (LONG i = l; i <= u; ++i) {
		BYTE v = 0; if (FAILED(SafeArrayGetElement(sa, &i, &v))) return false;
		out[size_t(i - l)] = v;
	}
	return true;
}


// ��ȡ BSTR/VARIANT Ϊ���ַ���
static std::wstring GetBstrProp(IWbemClassObject* obj, LPCWSTR name) {
	VARIANT vt; VariantInit(&vt);
	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr)) && vt.vt == VT_BSTR && vt.bstrVal) {
		std::wstring s = vt.bstrVal;
		VariantClear(&vt);
		return s;
	}
	VariantClear(&vt);
	return L"";
}

static ULONGLONG GetU64Prop(IWbemClassObject* obj, LPCWSTR name) {
	VARIANT vt; VariantInit(&vt);
	ULONGLONG v = 0;
	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr))) {
		if (vt.vt == VT_BSTR && vt.bstrVal) { // WMI �� Size �����ַ���
			v = _wcstoui64(vt.bstrVal, nullptr, 10);
		}
		else if (vt.vt == VT_I8) {
			v = static_cast<ULONGLONG>(vt.llVal);
		}
		else if (vt.vt == VT_UI8) {
			v = vt.ullVal;
		}
	}
	VariantClear(&vt);
	return v;
}

static bool GetBoolProp(IWbemClassObject* obj, LPCWSTR name, bool defval = false) {
	VARIANT vt; VariantInit(&vt);
	bool ret = defval;
	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr))) {
		if (vt.vt == VT_BOOL) ret = (vt.boolVal == VARIANT_TRUE);
		else if (vt.vt == VT_I4) ret = (vt.lVal != 0);
	}
	VariantClear(&vt);
	return ret;
}



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


// ��ʼ�� COM ������� WMI ����
void InitializeWMI(IWbemServices** pSvc, IWbemLocator** pLoc) {
	HRESULT hres;

	// ��ʼ�� COM ��
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		std::cerr << "COM initialization failed!" << std::endl;
		exit(1);
	}

	// ���� COM ��ȫ��
	hres = CoInitializeSecurity(
		NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);
	if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
		std::cerr << "Failed to initialize security!" << std::endl;
		CoUninitialize();
		exit(1);
	}

	// ���� IWbemLocator ����
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)pLoc);
	if (FAILED(hres)) {
		std::cerr << "Failed to create IWbemLocator object!" << std::endl;
		CoUninitialize();
		exit(1);
	}

	// ���ӵ� WMI ����
	hres = (*pLoc)->ConnectServer(
		BSTR(L"ROOT\\CIMV2"), // WMI �����ռ�
		NULL, NULL, 0, NULL, 0, 0, pSvc);
	if (FAILED(hres)) {
		std::cerr << "Failed to connect to WMI!" << std::endl;
		(*pLoc)->Release();
		CoUninitialize();
		exit(1);
	}

	// ���� WMI ����ȫ��
	hres = CoSetProxyBlanket(
		*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres)) {
		std::cerr << "Failed to set proxy blanket!" << std::endl;
		(*pSvc)->Release();
		(*pLoc)->Release();
		CoUninitialize();
		exit(1);
	}

}



std::string wStrToStr(wstring wstr) {
	std::wstring wideStr(wstr);
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &str[0], size_needed, nullptr, nullptr);
	return str;
}


//��ȡGPU��Ϣ
string QueryGPU(IWbemServices* pSvc) {

	wstringstream ostr;
	HRESULT hres;
	// ִ�в�ѯ��Win32_VideoController
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT AdapterCompatibility, Caption, Description, Name, PNPDeviceID,DeviceId, VideoProcessor FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnumerator);

	if (FAILED(hres)) {
		return "[VIDEO]" + wStrToStr(ostr.str()) + "[/VIDEO]";
	}

	// ��ȡ���
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	int index = 1;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;


	

		std::wstring vcac = GetBstrProp(pclsObj, L"AdapterCompatibility");
		std::wstring vcc = GetBstrProp(pclsObj, L"Caption");
		std::wstring vcd = GetBstrProp(pclsObj, L"Description");
		std::wstring vcn = GetBstrProp(pclsObj, L"Name");
		std::wstring vcpd = GetBstrProp(pclsObj, L"PNPDeviceID");
		std::wstring vcsn = GetBstrProp(pclsObj, L"DeviceId");
		std::wstring vcvp = GetBstrProp(pclsObj, L"VideoProcessor");

		ostr << L"<VCAC>" << vcac << L"</VCAC>"
			<< L"<VCC>" << vcc << L"</VCC>"
			<< L"<VCD>" << vcd << L"</VCD>"
			<< L"<VCDID>" << vcsn << L"</VCDID>"
			<< L"<VCN>" << vcn << L"</VCN>"
			<< L"<VCPDID>" << vcpd << L"</VCPDID>"
			<< L"<VCSN>" << vcsn << L"</VCSN>"
			<< L"<VCVP>" << vcvp << L"</VCVP>\r\n";
		pclsObj->Release();
	    index++;
	}
	pEnumerator->Release();


	return "[VIDEO]"+wStrToStr(ostr.str()) + "[/VIDEO]";


}

// �� WMI ReleaseDate ת�� Hex���� 20240212 �� 70120C00��
static std::wstring DateToHex(const std::wstring& wmiDate) {
	// WMI ��ʽ: YYYYMMDDHHMMSS.******
	if (wmiDate.size() < 8) return L"00000000";
	std::wstring y = wmiDate.substr(0, 4);
	std::wstring m = wmiDate.substr(4, 2);
	std::wstring d = wmiDate.substr(6, 2);
	unsigned yi = std::stoi(y) - 1980; // BIOS Encoded Offset
	unsigned mi = std::stoi(m);
	unsigned di = std::stoi(d);
	unsigned hex = (yi << 9) | (mi << 5) | (di);
	wchar_t buf[9]; swprintf(buf, 9, L"%08X", hex);
	return buf;
}


//��ȡGPU��Ϣ
string QueryBIOS(IWbemServices* pSvc) {

	wstringstream ostr;
	HRESULT hres;
	// ִ�в�ѯ��Win32_VideoController
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"),
		bstr_t("SELECT SMBIOSBIOSVersion, BIOSVersion, Manufacturer, SerialNumber, ReleaseDate FROM Win32_BIOS"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);
	if (FAILED(hres) || !pEnumerator) return  "[BIOS]" + wStrToStr(ostr.str()) + "[/BIOS]";


	IWbemClassObject* obj = nullptr; ULONG ret = 0;
	if (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &obj, &ret)) && ret == 1)
	{
		std::wstring v1 = GetBstrProp(obj, L"SMBIOSBIOSVersion");
		std::wstring v2 = GetUInt16ArrayStrProp(obj, L"BIOSVersion");
		std::wstring man = GetBstrProp(obj, L"Manufacturer");
		std::wstring sn = GetBstrProp(obj, L"SerialNumber");
		std::wstring date = GetBstrProp(obj, L"ReleaseDate");

		std::wstring v3 = man + L" - " + DateToHex(date);
		if (sn.empty()) sn = L"Not Applicable";

		ostr << L"<BIOSV1>" << v1 << L"</BIOSV1>"
			<< L"<BIOSV2>" << v2 << L"</BIOSV2>"
			<< L"<BIOSV3>" << v3 << L"</BIOSV3>"
			<< L"<BIOSSN>" << sn << L"</BIOSSN>\n";

		obj->Release();
	
	}
	pEnumerator->Release();


	return "[BIOS]" + wStrToStr(ostr.str()) + "[/BIOS]";


}


// ��ȡ�����豸��Ϣ
string QueryNetworkAdapters(IWbemServices* pSvc) {

	HRESULT hres;
	// ��ѯ�������������ã�Win32_NetworkAdapterConfiguration��
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_NetworkAdapter"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
		return "[NA][/NA][NPA][/NPA]";

	}

	// ��ȡ��ѯ���
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	wstring NPAText = L"";
	wstring NAText = L"";
	wstringstream  naOstr;
	wstringstream npaOstr;
	while (pEnumerator) {
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;
		wstring name = L"";
		wstring mac = L"";
		bool physical = false;
		// ��ȡ��������


		wstring Description = GetBstrProp(pclsObj, L"Description");
		wstring MACAddress = GetBstrProp(pclsObj, L"MACAddress");

		wstring PhysicalAdapter = (GetBoolProp(pclsObj, L"PhysicalAdapter") ? L"True" : L"False");

		naOstr << L"<NAPN>" << Description << "</NAPN><NAPA>" << PhysicalAdapter << "</NAPA>\r\n";


		MACAddress.erase(std::remove(MACAddress.begin(), MACAddress.end(), ':'), MACAddress.end());

		npaOstr << L"<EPAIN>" << Description << "</EPAIN><EPANPAA>" << MACAddress << "</EPANPAA>\r\n";


		pclsObj->Release();
	}




	return "[NA]" + wStrToStr(naOstr.str()) + "[/NA]\r\n[NPA]" + wStrToStr(npaOstr.str()) + "[/NPA]";

	// ����
	pEnumerator->Release();
}


// ��ȡ DISPLAY ��Ϣ
string queryDisplay(IWbemServices* pSvc) {

	HRESULT hres;
	// ��ѯ CPU ��Ϣ
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		// Name��DriverVersion��CurrentRefreshRate��Caption/PNPDeviceID
		bstr_t(L"SELECT Name, DriverVersion, CurrentRefreshRate, Caption, PNPDeviceID FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnumerator);
	if (FAILED(hres)) {

		return "[DISPLAY][/DISPLAY]";
	}

	// ��ȡ��ѯ���
	ULONG uReturn = 0;
	wstringstream ostr;
	while (pEnumerator) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;

		std::wstring name = GetBstrProp(obj, L"Name");            // DCDN
		std::wstring drv = GetBstrProp(obj, L"DriverVersion");   // DCDV
		ULONGLONG         hz = GetU64Prop(obj, L"CurrentRefreshRate"); // DCDF��Hz��
		std::wstring cap = GetBstrProp(obj, L"Caption");
		std::wstring pnpId = GetBstrProp(obj, L"PNPDeviceID");

		// DCSID ������ PNPDeviceID
		std::wstring dcsid = !pnpId.empty() ? pnpId : (!cap.empty() ? cap : name);

		// ��ĳЩ�������� 0���ɰ����ΪĬ�� 60
		if (hz <= 0) hz = 60;

		ostr << L"<DCDN>" << (name.empty() ? L"UNKNOWN" : name) << L"</DCDN>"
			<< L"<DCDF>" << hz << L"</DCDF>"
			<< L"<DCDV>" << (drv.empty() ? L"UNKNOWN" : drv) << L"</DCDV>"
			<< L"<DCSID>" << (dcsid.empty() ? L"UNKNOWN" : dcsid) << L"</DCSID>\r\n";

		obj->Release();

	}

	// ����
	pEnumerator->Release();
	return "[DISPLAY]" + wStrToStr(ostr.str()) + "[/DISPLAY]";

}



// ��ȡ monitor ��Ϣ
string queryMonitor() {

	wstringstream ostr;
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) 	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";;

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE, nullptr);
	// �������ѳ�ʼ�����ɺ���

	IWbemLocator* pLoc = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr) || !pLoc) { CoUninitialize();	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";
	}

	IWbemServices* pSvc = nullptr;
	// ע�⣺��������Ϣ�� root\WMI �����ռ�
	hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
	if (FAILED(hr) || !pSvc) { pLoc->Release(); CoUninitialize(); 	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]"; }
	// 3) ������ CreateInstanceEnum ֱ��ö�٣��� ExecQuery ���ȣ�
	IEnumWbemClassObject* pEnum = nullptr;
	hr = pSvc->CreateInstanceEnum(_bstr_t(L"WmiMonitorID"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnum);

	// 4) Ҳ�� pEnum ��һ�� blanket���ؼ���
	CoSetProxyBlanket(pEnum, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);


	// ��ȡ��ѯ���
	ULONG uReturn = 0;

	while (pEnum) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hr = pEnum->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;

		bool active = GetBoolProp(obj, L"Active", true);
		std::wstring inst = GetBstrProp(obj, L"InstanceName");
		ULONG wk = GetULongProp(obj, L"WeekOfManufacture");
		ULONG yr = GetULongProp(obj, L"YearOfManufacture");

		ostr << L"<WMIDA>" << (active ? L"True" : L"False") << L"</WMIDA>";
		ostr << L"<WMIDIN>" << (inst.empty() ? L"UNKNOWN" : inst) << L"</WMIDIN>";

		ostr << L"<WMIDMN>"<< GetUInt16ArrayStrProp(obj, L"ManufacturerName");
		ostr<< L"</WMIDMN>";
		ostr << L"<WMIDPCID>" << GetUInt16ArrayStrProp(obj, L"ProductCodeID");
		ostr << L"</WMIDPCID>";
		ostr << L"<WMIDSNID>" << GetUInt16ArrayStrProp(obj, L"SerialNumberID");
		ostr << L"</WMIDSNID>";
		ostr << L"<WMIDUFN>" << GetUInt16ArrayStrProp(obj, L"UserFriendlyName");
		ostr<< L"</WMIDUFN>";
		ostr << L"<WMIDWM>" << wk << L"</WMIDWM>";
		ostr << L"<WMIDYM>" << yr << L"</WMIDYM>\r\n";
		obj->Release();
	}

	// ����
	pEnum->Release();
	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";

}


// ���� SMBIOS ԭʼ���ҵ� Type 1��System Information������ȡ UUID �� 16 �ֽ�
static bool ExtractUuidFromSMBIOS(const std::vector<uint8_t>& data, std::vector<uint8_t>& uuid16) {
	size_t i = 0;
	while (i + 4 <= data.size()) {
		// �ṹͷ��Type(1) Length(1) Handle(2)
		uint8_t type = data[i + 0];
		uint8_t len = data[i + 1];
		if (len < 4 || i + len > data.size()) break;

		if (type == 1) { // System Information (Type 1)
			// UUID ���淶�� offset 0x08 �� 16 �ֽڣ�SMBIOS 2.6+��
			if (len >= 0x18 && i + 0x08 + 16 <= data.size()) {
				uuid16.assign(data.begin() + i + 0x08, data.begin() + i + 0x08 + 16);
				return true;
			}
		}

		// ������ʽ�������������ַ������ϣ�ֱ������˫ 0 ����
		size_t j = i + len; // �ַ��������
		while (j + 1 < data.size()) {
			if (data[j] == 0x00 && data[j + 1] == 0x00) { j += 2; break; }
			// ����һ���� 0 ��β���ַ���
			while (j < data.size() && data[j] != 0x00) ++j;
			if (j < data.size() && data[j] == 0x00) ++j;
		}
		i = j;
	}
	return false;
}


// ��ȡ bios ��Ϣ
string querySmbios() {

	std::wstringstream ostr;
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) return "[SMBIOSUUID][/SMBIOSUUID]";

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE, nullptr); // ���ѳ�ʼ���ɺ��Է���

	IWbemLocator* pLoc = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr) || !pLoc) { CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	// �ؼ���ROOT\WMI
	IWbemServices* pSvc = nullptr;
	hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
	if (FAILED(hr) || !pSvc) { pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
	if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	IEnumWbemClassObject* pEnum = nullptr;
	// ��ȡԭʼ SMBIOS ��
	hr = pSvc->ExecQuery(bstr_t(L"WQL"),
		bstr_t(L"SELECT SMBiosData FROM MSSmBios_RawSMBiosTables"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
	if (FAILED(hr) || !pEnum) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	// ��ö����Ҳ��һ�� blanket����Щ������Ҫ��
	CoSetProxyBlanket(pEnum, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

	IWbemClassObject* obj = nullptr; ULONG ret = 0;
	hr = pEnum->Next(WBEM_INFINITE, 1, &obj, &ret);
	if (FAILED(hr) || ret == 0 || !obj) {
		if (pEnum) pEnum->Release(); pSvc->Release(); pLoc->Release(); CoUninitialize();
		return "[SMBIOSUUID]" + wStrToStr(ostr.str()) + "[/SMBIOSUUID]";
	}

	// ȡ SMBiosData�������� SAFEARRAY��
	VARIANT vt; VariantInit(&vt);
	std::vector<uint8_t> raw;
	if (SUCCEEDED(obj->Get(L"SMBiosData", 0, &vt, nullptr, nullptr)) && SafeArrayToBytes(vt, raw)) {
		std::vector<uint8_t> uuid16;
		bool ok = ExtractUuidFromSMBIOS(raw, uuid16);

		ostr << L"<SMBULA>" << (ok ? L"True" : L"False") << L"</SMBULA>";
		ostr << L"<SMBULC>1</SMBULC>";
		ostr << L"<SMBULIN>SMBiosData</SMBULIN>";
		ostr << L"<SMBULLU>";
		if (ok) {
			for (size_t i = 0; i < uuid16.size(); ++i) {
				if (i)ostr << L" ";
				ostr << (unsigned)uuid16[i];
			}
		}
		ostr << L"</SMBULLU>\r\n";
	}
	VariantClear(&vt);
	obj->Release();

	pEnum->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();
	return "[SMBIOSUUID]"+wStrToStr(ostr.str()) + "[/SMBIOSUUID]";

}




// ��ȡ CPU ��Ϣ
string GetCPUInfo(IWbemServices* pSvc) {

	HRESULT hres;
	// ��ѯ CPU ��Ϣ
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {

		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// ��ȡ��ѯ���
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	ULONGLONG NumberOfCores = 0;
	ULONGLONG NumberOfLogicalProcessors = 0;
	std::wstringstream cpuStr;
	wstringstream sysStr;
	while (pEnumerator) {
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;

		VARIANT vtProp;
		wstring PN = GetBstrProp(pclsObj, L"Name");
		wstring PDID = GetBstrProp(pclsObj, L"DeviceId");
		ULONGLONG NumberOfCoresTemp = GetU64Prop(pclsObj, L"NumberOfCores");
		if (NumberOfCoresTemp)
		{
			NumberOfCores = NumberOfCores + NumberOfCoresTemp;
		}

		ULONGLONG NumberOfLogicalProcessorsTemp = GetU64Prop(pclsObj, L"NumberOfLogicalProcessors");
		if (NumberOfLogicalProcessorsTemp)
		{
			NumberOfLogicalProcessors = NumberOfLogicalProcessors + NumberOfLogicalProcessorsTemp;
		}


		//<PDID>CPU0</PDID><PN>11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz</PN><PNC>8</PNC><PNEC>8</PNEC><PNLP>16</PNLP>
		cpuStr << L"<PDID>" << PDID << "</PDID><PN>" << PN << "</PN><PNC>" << NumberOfCoresTemp << "</PNC><PNEC>" << NumberOfCoresTemp << "</PNEC><PNLP>" << NumberOfLogicalProcessorsTemp << "</PNLP>\r\n";
		pclsObj->Release();
	}
	sysStr << L"[SYS]<CSNP>" << NumberOfCores << "</CSNP><CSNLP>" << NumberOfLogicalProcessors << "</CSNLP>[/SYS]\r\n"
		<< "[CPU]" << cpuStr.str() << "[/CPU]";

	// ����
	pEnumerator->Release();
	return wStrToStr(sysStr.str());

}


// ���� PNPDeviceID ���˲�ѯ PhysicalMedia.SerialNumber��ĳЩƷ�� DiskDrive.SerialNumber Ϊ�գ�
static std::wstring QueryPhysicalMediaSerialByPNP(IWbemServices* pSvc, const std::wstring& pnpId) {
	if (pnpId.empty()) return L"";
	// ע�⣺Win32_PhysicalMedia.Tag ͨ���� Win32_DiskDrive.DeviceID �� PNP ��أ�����Ӧ��ʵ�ָ���
	// ������������ֱ�� SELECT * FROM Win32_PhysicalMedia Ȼ����ƥ�� SerialNumber ��Ϊ�յ���
	IEnumWbemClassObject* pEnum = nullptr;
	HRESULT hr = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		bstr_t(L"SELECT SerialNumber FROM Win32_PhysicalMedia"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnum);
	if (FAILED(hr) || !pEnum) return L"";

	std::wstring serial;
	while (true) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hr = pEnum->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;
		std::wstring s = GetBstrProp(obj, L"SerialNumber");
		if (!s.empty()) { serial = s; obj->Release(); break; }
		obj->Release();
	}
	if (pEnum) pEnum->Release();
	return serial;
}


string QueryDiskDrives(IWbemServices* pSvc) {
	HRESULT hres;

	// ��ѯ���̵� WMI ��ѯ���
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		BSTR(L"WQL"),
		BSTR(L"SELECT * FROM Win32_DiskDrive"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres)) {

		return "[DISK][/DISK]";
	}

	// ��ȡ������Ϣ
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	std::wstring diskListText;
	while (pEnumerator) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;

		std::wstring status = GetBstrProp(obj, L"Status");           // "OK" / "Degraded" ��
		bool         loaded = GetBoolProp(obj, L"MediaLoaded", true);// �Ƿ��н��ʣ�SSD/HDD �̶�����ͨ��Ϊ true��
		std::wstring did = GetBstrProp(obj, L"DeviceID");         // \\.\PHYSICALDRIVE0
		std::wstring ifType = GetBstrProp(obj, L"InterfaceType");    // "IDE"/"SCSI"/"NVMe"/"USB" ��
		std::wstring model = GetBstrProp(obj, L"Model");            // �ͺ�
		std::wstring fwrev = GetBstrProp(obj, L"FirmwareRevision"); // �̼��汾
		std::wstring sn = GetBstrProp(obj, L"SerialNumber");     // ĳЩ���̿���Ϊ�ջ��пո�
		ULONGLONG    size = GetU64Prop(obj, L"Size");              // �ֽ�
		std::wstring pnp = GetBstrProp(obj, L"PNPDeviceID");      // ��Ҫʱ�����

		// ȥ�����кŵ�β���հ�
		if (!sn.empty()) {
			while (!sn.empty() && (sn.back() == L' ' || sn.back() == L'\t')) sn.pop_back();
		}
		// ���ˣ���� DiskDrive.SerialNumber Ϊ�գ��� PhysicalMedia.SerialNumber
		if (sn.empty()) {
			std::wstring alt = QueryPhysicalMediaSerialByPNP(pSvc, pnp);
			if (!alt.empty()) sn = alt;
		}

		// ���Ϊ��ı�ǩ��ʽ
		std::wstringstream diskText;
		diskText << L"<DS>" << (status.empty() ? L"OK" : status) << L"</DS>"
			<< L"<DL>" << (loaded ? L"True" : L"False") << L"</DL>"
			<< L"<DID>" << did << L"</DID>"
			<< L"<DIT>" << (ifType.empty() ? L"Unknown" : ifType) << L"</DIT>"
			<< L"<DM>" << model << L"</DM>"
			<< L"<DFR>" << fwrev << L"</DFR>"
			<< L"<DSN>" << (sn.empty() ? L"UNKNOWN" : sn) << L"</DSN>"
			<< L"<DSize>" << size << L"</DSize>";
		diskListText = diskListText + diskText.str() + L"\r\n";
		obj->Release();

	}

	pEnumerator->Release();

	return "[DISK]" + wStrToStr(diskListText) + "[/DISK]";


}


// �ͷ���Դ
void CleanUpWMI(IWbemServices* pSvc, IWbemLocator* pLoc) {
	if (pSvc) pSvc->Release();
	if (pLoc) pLoc->Release();
	CoUninitialize();
}

void report() {
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	InitializeWMI(&pSvc, &pLoc);
	string systemInfo = "[SystemInfo]\r\n";
	//[NT]10.0.19045.5607[/NT]
	string windowVersion = GetWindowsVersion();
	systemInfo.append("[" + windowVersion + "]\r\n");
	//[SYS]<CSMf>HASEE Computer</CSMf><CSM>CNH5S</CSM><CSTPM>16948453376</CSTPM><CSNP>1</CSNP><CSNLP>16</CSNLP>
	string sysProcessor = "";
	string processorCoresInfoText = GetCPUInfo(pSvc);
	sysProcessor = sysProcessor + processorCoresInfoText;
	systemInfo.append(sysProcessor);
	//[UPTimeTick]750484[/UPTimeTick]
	//[UPTime] 0d0h12m30s[/ UPTime]
	string systemUpTimeText = "\r\n[UPTime]" + GetSystemUptime() + "[/UPTime]";
	string systemInstallDateText = "\r\n[OSInstallDate]" + GetInstallDate() + "[/OSInstallDate]";
	systemInfo.append(systemUpTimeText + systemInstallDateText + "\r\n");
	//[NA] <NAPN>WAN Miniport(IP) < / NAPN > <NAPA>False< / NAPA>
	//	<NAPN>WAN Miniport(IPv6) < / NAPN > <NAPA>False< / NAPA>
	//	<NAPN>Intel(R) Wireless - AC 9462 < / NAPN > <NAPA>True< / NAPA>
	//	<NAPN>WAN Miniport(Network Monitor) < / NAPN > <NAPA>False< / NAPA>
	//	<NAPN>Microsoft Wi - Fi Direct Virtual Adapter< / NAPN><NAPA>False< / NAPA>
	//	<NAPN>Microsoft Wi - Fi Direct Virtual Adapter< / NAPN><NAPA>False< / NAPA>
	//	<NAPN>Intel(R) Ethernet Connection(14) I219 - V< / NAPN><NAPA>True< / NAPA>
	//	<NAPN>Bluetooth Device(Personal Area Network) < / NAPN > <NAPA>True< / NAPA>
	string networkAdaptersText = QueryNetworkAdapters(pSvc);
	systemInfo.append(networkAdaptersText + "\r\n");
	//[GPU]<GN></GN><GID></GID>[/GPU]

	string GpuText = QueryGPU(pSvc);
	systemInfo.append(GpuText + "\r\n");
	/*[DISK] <DS>OK< / DS><DL>True< / DL><DID>\\.\PHYSICALDRIVE0< / DID><DIT>IDE< / DIT><DM>M.2 SATA M1912 - 1TB< / DM><DFR>V0915A0< / DFR><DSN>XLXWKWY2022001425< / DSN> < DSize>1024203640320 < / DSize >
		<DS>OK< / DS><DL>True< / DL><DID>\\.\PHYSICALDRIVE1< / DID><DIT>SCSI< / DIT><DM>KINGSTON SNV3S500G< / DM><DFR>SDQ00103< / DFR> < DSN>0000_0000_0000_0000_0026_B728_371C_6E95.< / DSN> < DSize>500105249280 < / DSize >
		[/ DISK]*/
	string diskText = QueryDiskDrives(pSvc);
	systemInfo.append(diskText + "\r\n");
	string displayText = queryDisplay(pSvc);
	systemInfo.append(displayText+"\r\n");
	CleanUpWMI(pSvc, pLoc);
	/*[MONITOR] <WMIDA>True< / WMIDA><WMIDIN>DISPLAY\CMN1521\4 & 38d80a36 & 0 & UID8388688_0< / WMIDIN> < WMIDMN>67 77 78 0 0 0 0 0 0 0 0 0 0 0 0 0 < / WMIDMN > < WMIDPCID>49 53 50 49 0 0 0 0 0 0 0 0 0 0 0 0 < / WMIDPCID > < WMIDSNID>48 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 < / WMIDSNID > < WMIDWM>1 < / WMIDWM > < WMIDYM>2020 < / WMIDYM >
		<WMIDA>True< / WMIDA><WMIDIN>DISPLAY\SGTBC32\4 & 38d80a36 & 0 & UID4145_0< / WMIDIN> < WMIDMN>83 71 84 0 0 0 0 0 0 0 0 0 0 0 0 0 < / WMIDMN > < WMIDPCID>66 67 51 50 0 0 0 0 0 0 0 0 0 0 0 0 < / WMIDPCID > < WMIDSNID>49 54 56 52 51 48 48 57 0 0 0 0 0 0 0 0 < / WMIDSNID > < WMIDUFN>72 68 77 73 0 0 0 0 0 0 0 0 0 < / WMIDUFN > < WMIDWM>25 < / WMIDWM > < WMIDYM>2023 < / WMIDYM >
		[/ MONITOR]*/
	string monitor = queryMonitor();
	systemInfo.append(monitor+"\r\n");
		/*[SMBIOSUUID]<SMBULA>True< / SMBULA> < SMBULC>1 < / SMBULC > <SMBULIN>SMBiosData< / SMBULIN> < SMBULLU>0 0 150 240 0 0 0 16 128 0 0 224 76 142 197 223 < / SMBULLU >
			[/ SMBIOSUUID]*/
	 string smbios = querySmbios();
	 systemInfo.append(smbios+"\r\n");

	 InitializeWMI(&pSvc, &pLoc);
	 string bios = QueryBIOS(pSvc);
	 systemInfo.append(bios);


	std::cout << systemInfo << std::endl;


		CleanUpWMI(pSvc, pLoc);
	return;



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