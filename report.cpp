

#include "report.h"


#define CpuNum "wmic cpu get DeviceID"
// 命令调取 Cpu 物理核数
#define CpuCoreNum "wmic cpu get NumberOfCores"
// 命令调取 Cpu 逻辑核数
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


// 读取 uint8/uint16 的标量
static ULONG GetULongProp(IWbemClassObject* obj, LPCWSTR name, ULONG defVal = 0) {
	VARIANT vt; VariantInit(&vt);
	ULONG v = defVal;
	if (SUCCEEDED(obj->Get(name, 0, &vt, nullptr, nullptr))) {
		if (vt.vt == VT_UI1) v = vt.bVal;            // WeekOfManufacture（byte）
		else if (vt.vt == VT_UI2) v = vt.uiVal;      // YearOfManufacture（uint16）
		else if (vt.vt == VT_I4) v = (ULONG)vt.lVal; // 兼容某些实现
		else if (vt.vt == VT_BSTR && vt.bstrVal) v = (ULONG)_wtol(vt.bstrVal);
	}
	VariantClear(&vt);
	return v;
}





// 打印 UINT16 数组为“空格分隔的十进制”，示例：83 71 84 0 ...
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


// 读取 BSTR/VARIANT 为宽字符串
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
		if (vt.vt == VT_BSTR && vt.bstrVal) { // WMI 的 Size 常是字符串
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



// 定义 RtlGetVersion 函数类型
typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);
using namespace std;

using namespace Gdiplus;

bool GetEncoderClsid(const WCHAR* pszFormat, CLSID* pClsid);

// 初始化 GDI+（用于保存图像）
void InitGDIPlus() {
	Gdiplus::GdiplusStartupInput gdiPlusStartupInput;
	ULONG_PTR gdiPlusToken;
	Gdiplus::GdiplusStartup(&gdiPlusToken, &gdiPlusStartupInput, nullptr);
}

// 关闭 GDI+
void ShutdownGDIPlus(ULONG_PTR gdiPlusToken) {
	Gdiplus::GdiplusShutdown(gdiPlusToken);
}
// 压缩文件为 Gzip 格式
bool compressGzipFile(const std::string& sourceFilename, const std::string& destFilename) {
	// 打开源文件
	std::ifstream sourceFile(sourceFilename, std::ios_base::binary);
	if (!sourceFile.is_open()) {
		std::cerr << "Failed to open source file!" << std::endl;
		return false;
	}

	// 打开目标文件（压缩后的 Gzip 文件）
	std::ofstream destFile(destFilename, std::ios_base::binary);
	if (!destFile.is_open()) {
		std::cerr << "Failed to open destination file!" << std::endl;
		return false;
	}

	// 写 Gzip 文件头
	unsigned char header[10] = { 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };  // Gzip header
	destFile.write(reinterpret_cast<char*>(header), sizeof(header));

	// 初始化 zlib 压缩流
	z_stream strm = { 0 };
	int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		std::cerr << "deflateInit2 failed!" << std::endl;
		return false;
	}

	// 设置缓冲区
	std::vector<char> buffer(1024); // 1KB 缓冲区

	// 压缩数据流
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

	// 压缩结束后清理
	ret = deflateEnd(&strm);
	if (ret != Z_OK) {
		std::cerr << "deflateEnd failed!" << std::endl;
		return false;
	}

	// 写 CRC 和文件大小（Gzip 文件尾）
	unsigned crc = crc32(0L, Z_NULL, 0);
	unsigned size = static_cast<unsigned>(sourceFile.gcount());
	destFile.write(reinterpret_cast<char*>(&crc), sizeof(crc));
	destFile.write(reinterpret_cast<char*>(&size), sizeof(size));

	return true;
}

// 将位图保存到内存流中
void SaveBitmapToMemory(HBITMAP hBitmap, std::vector<BYTE>& imageData, ULONG quality) {
	// 创建 GDI+ 位图对象
	Gdiplus::Bitmap bitmap(hBitmap, nullptr);

	// 创建内存流对象
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

	// 设置压缩参数
	Gdiplus::EncoderParameters encoderParams;
	memset(&encoderParams, 0, sizeof(encoderParams));
	encoderParams.Count = 1;
	Gdiplus::EncoderParameters encoderParameters;
	encoderParameters.Count = 1;
	encoderParameters.Parameter[0].Guid = Gdiplus::EncoderQuality;
	encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
	encoderParameters.Parameter[0].NumberOfValues = 1;
	encoderParameters.Parameter[0].Value = &quality;


	// 保存为内存流
	Gdiplus::Status status = bitmap.Save(pStream, &encoderClsid, &encoderParams);
	if (status != Gdiplus::Ok) {
		std::cerr << "Failed to save bitmap to memory" << std::endl;
		pStream->Release();
		return;
	}

	// 获取流数据大小
	ULARGE_INTEGER liSize;
	hr = pStream->Seek({ 0 }, STREAM_SEEK_END, &liSize);
	if (FAILED(hr)) {
		std::cerr << "Failed to seek to the end of the stream" << std::endl;
		pStream->Release();
		return;
	}

	// 确保流大小正确
	DWORD dwSize = static_cast<DWORD>(liSize.QuadPart);
	imageData.resize(dwSize);

	// 移动流指针到起始位置
	pStream->Seek({ 0 }, STREAM_SEEK_SET, nullptr);

	// 读取流数据到 imageData
	ULONG bytesRead;
	hr = pStream->Read(imageData.data(), dwSize, &bytesRead);
	if (FAILED(hr) || bytesRead != dwSize) {
		std::cerr << "Failed to read data from memory stream" << std::endl;
	}

	// 清理资源
	pStream->Release();
}

// 将内存中的字节数据保存到文件
void SaveMemoryToFile(const std::vector<BYTE>& imageData, const std::wstring& filename) {
	// 使用 std::ofstream 打开文件进行写入
	std::ofstream file(filename, std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file for writing" << std::endl;
		return;
	}

	// 将内存中的字节数据写入文件
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

	// 重置状态
	stat = GenericError;

	// Get an image from the disk.
	Image* pImage = new Image(pszOriFilePath);

	do {
		if (NULL == pImage) {
			break;
		}

		// 获取长宽
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




// 截取桌面并保存为文件
void CaptureDesktop(const std::wstring& filename) {
	// 获取屏幕 DC
	HDC hScreenDC = GetDC(nullptr);
	if (hScreenDC == nullptr) {
		std::cerr << "Failed to get screen DC" << std::endl;
		return;
	}

	// 获取屏幕尺寸
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	// 创建内存 DC
	HDC hMemDC = CreateCompatibleDC(hScreenDC);
	if (hMemDC == nullptr) {
		std::cerr << "Failed to create memory DC" << std::endl;
		ReleaseDC(nullptr, hScreenDC);
		return;
	}

	// 创建与屏幕兼容的位图
	HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
	if (hBitmap == nullptr) {
		std::cerr << "Failed to create bitmap" << std::endl;
		DeleteDC(hMemDC);
		ReleaseDC(nullptr, hScreenDC);
		return;
	}

	// 将屏幕内容复制到内存 DC 中
	SelectObject(hMemDC, hBitmap);
	if (!BitBlt(hMemDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY)) {
		std::cerr << "BitBlt failed" << std::endl;
	}
	else {

		// SaveBitmapToFile(hBitmap, L"desktop_screenshot_compressed.jpg");
		std::vector<BYTE> imageData;
		//// 捕获桌面并保存到内存
		SaveBitmapToMemory(hBitmap, imageData, 30);
		std::wstring filename = L"screenshot_in_memory.jpeg";
		SaveMemoryToFile(imageData, filename);

		// CompressImageQuality(L"desktop_screenshot_compressed.jpg", L"1C.jpg", 30);
	}

	// 清理资源
	DeleteObject(hBitmap);
	DeleteDC(hMemDC);
	ReleaseDC(nullptr, hScreenDC);
}



// 解压 Gzip 文件
bool decompressGzipFile(const std::string& sourceFilename, const std::string& destFilename) {
	// 打开源文件（Gzip 压缩文件）
	std::ifstream sourceFile(sourceFilename, std::ios_base::binary);
	if (!sourceFile.is_open()) {
		std::cerr << "Failed to open source file!" << std::endl;
		return false;
	}

	// 打开目标文件
	std::ofstream destFile(destFilename, std::ios_base::binary);
	if (!destFile.is_open()) {
		std::cerr << "Failed to open destination file!" << std::endl;
		return false;
	}

	// 跳过 Gzip 文件头（10 字节）
	sourceFile.seekg(10, std::ios::beg);

	// 初始化 zlib 解压流
	z_stream strm = { 0 };
	int ret = inflateInit2(&strm, 16 + MAX_WBITS);  // 16 + MAX_WBITS 表示 Gzip 格式
	if (ret != Z_OK) {
		std::cerr << "inflateInit2 failed!" << std::endl;
		return false;
	}

	// 设置缓冲区
	std::vector<char> buffer(1024); // 1KB 缓冲区

	// 解压数据流
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

	// 解压结束后清理
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
	// 获取版本信息
	RTL_OSVERSIONINFOW osvi;
	ZeroMemory(&osvi, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	// 获取 RtlGetVersion 地址
	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

	if (RtlGetVersion != nullptr) {
		NTSTATUS status = RtlGetVersion(&osvi);
		if (status == 0) {  // 0 表示成功
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



// 获取总内存大小（MB）
long getTotalMemory() {
	MEMORYSTATUSEX stat;
	stat.dwLength = sizeof(stat);
	GlobalMemoryStatusEx(&stat);
	return stat.ullTotalPhys / (1024 * 1024);  // 转换为 MB
}

// 手动实现 popcount 计算
int popcount64(uint64_t value) {
	int count = 0;
	while (value) {
		count += value & 1;  // 如果最低位为 1，则计数
		value >>= 1;          // 右移 1 位，检查下一位
	}
	return count;
}



string GetInstallDate() {
	HKEY hKey;
	DWORD installDate;
	DWORD bufferSize = sizeof(installDate);

	// 打开注册表键
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS) {

		// 读取 InstallDate 键
		if (RegQueryValueExW(hKey, L"InstallDate", nullptr, nullptr, (LPBYTE)&installDate, &bufferSize) == ERROR_SUCCESS) {
			// 注册表中的时间是从 1970 年 1 月 1 日开始的秒数
			time_t installTime = installDate;

			// 将安装时间转换为可读的日期格式
			struct tm timeInfo = { 0 };  // 使用 `{0}` 初始化结构
			localtime_s(&timeInfo, &installTime);
			char installDateStr[80];
			strftime(installDateStr, sizeof(installDateStr), "%Y-%m-%d %H:%M:%S", &timeInfo);

			return  installDateStr;
		}
		else {
			return "";
		}

		// 关闭注册表键
		RegCloseKey(hKey);
	}
	else {
		return "";
	}
}


string GetSystemUptime() {
	// 获取系统启动后的时间，单位是毫秒
	DWORD64 uptime = GetTickCount64();

	// 计算系统运行时间（转换为小时、分钟、秒）
	DWORD64 seconds = uptime / 1000;
	DWORD64 minutes = seconds / 60;
	DWORD64 hours = minutes / 60;
	DWORD64 days = hours / 24;
	stringstream oss;
	oss << days << "d" << hours % 24 << "h"
		<< minutes % 60 << "m" << seconds % 60 << "s";
	return oss.str();
}


// 初始化 COM 库和设置 WMI 服务
void InitializeWMI(IWbemServices** pSvc, IWbemLocator** pLoc) {
	HRESULT hres;

	// 初始化 COM 库
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		std::cerr << "COM initialization failed!" << std::endl;
		exit(1);
	}

	// 设置 COM 安全性
	hres = CoInitializeSecurity(
		NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);
	if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
		std::cerr << "Failed to initialize security!" << std::endl;
		CoUninitialize();
		exit(1);
	}

	// 创建 IWbemLocator 对象
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)pLoc);
	if (FAILED(hres)) {
		std::cerr << "Failed to create IWbemLocator object!" << std::endl;
		CoUninitialize();
		exit(1);
	}

	// 连接到 WMI 服务
	hres = (*pLoc)->ConnectServer(
		BSTR(L"ROOT\\CIMV2"), // WMI 命名空间
		NULL, NULL, 0, NULL, 0, 0, pSvc);
	if (FAILED(hres)) {
		std::cerr << "Failed to connect to WMI!" << std::endl;
		(*pLoc)->Release();
		CoUninitialize();
		exit(1);
	}

	// 设置 WMI 代理安全性
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


//获取GPU信息
string QueryGPU(IWbemServices* pSvc) {

	wstringstream ostr;
	HRESULT hres;
	// 执行查询：Win32_VideoController
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT AdapterCompatibility, Caption, Description, Name, PNPDeviceID,DeviceId, VideoProcessor FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnumerator);

	if (FAILED(hres)) {
		return "[VIDEO]" + wStrToStr(ostr.str()) + "[/VIDEO]";
	}

	// 读取结果
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

// 把 WMI ReleaseDate 转成 Hex（如 20240212 → 70120C00）
static std::wstring DateToHex(const std::wstring& wmiDate) {
	// WMI 格式: YYYYMMDDHHMMSS.******
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


//获取GPU信息
string QueryBIOS(IWbemServices* pSvc) {

	wstringstream ostr;
	HRESULT hres;
	// 执行查询：Win32_VideoController
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


// 获取网卡设备信息
string QueryNetworkAdapters(IWbemServices* pSvc) {

	HRESULT hres;
	// 查询网络适配器配置（Win32_NetworkAdapterConfiguration）
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_NetworkAdapter"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
		return "[NA][/NA][NPA][/NPA]";

	}

	// 获取查询结果
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
		// 获取网卡名称


		wstring Description = GetBstrProp(pclsObj, L"Description");
		wstring MACAddress = GetBstrProp(pclsObj, L"MACAddress");

		wstring PhysicalAdapter = (GetBoolProp(pclsObj, L"PhysicalAdapter") ? L"True" : L"False");

		naOstr << L"<NAPN>" << Description << "</NAPN><NAPA>" << PhysicalAdapter << "</NAPA>\r\n";


		MACAddress.erase(std::remove(MACAddress.begin(), MACAddress.end(), ':'), MACAddress.end());

		npaOstr << L"<EPAIN>" << Description << "</EPAIN><EPANPAA>" << MACAddress << "</EPANPAA>\r\n";


		pclsObj->Release();
	}




	return "[NA]" + wStrToStr(naOstr.str()) + "[/NA]\r\n[NPA]" + wStrToStr(npaOstr.str()) + "[/NPA]";

	// 清理
	pEnumerator->Release();
}


// 获取 DISPLAY 信息
string queryDisplay(IWbemServices* pSvc) {

	HRESULT hres;
	// 查询 CPU 信息
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		// Name、DriverVersion、CurrentRefreshRate、Caption/PNPDeviceID
		bstr_t(L"SELECT Name, DriverVersion, CurrentRefreshRate, Caption, PNPDeviceID FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnumerator);
	if (FAILED(hres)) {

		return "[DISPLAY][/DISPLAY]";
	}

	// 获取查询结果
	ULONG uReturn = 0;
	wstringstream ostr;
	while (pEnumerator) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;

		std::wstring name = GetBstrProp(obj, L"Name");            // DCDN
		std::wstring drv = GetBstrProp(obj, L"DriverVersion");   // DCDV
		ULONGLONG         hz = GetU64Prop(obj, L"CurrentRefreshRate"); // DCDF（Hz）
		std::wstring cap = GetBstrProp(obj, L"Caption");
		std::wstring pnpId = GetBstrProp(obj, L"PNPDeviceID");

		// DCSID 优先用 PNPDeviceID
		std::wstring dcsid = !pnpId.empty() ? pnpId : (!cap.empty() ? cap : name);

		// 若某些驱动返回 0，可按需改为默认 60
		if (hz <= 0) hz = 60;

		ostr << L"<DCDN>" << (name.empty() ? L"UNKNOWN" : name) << L"</DCDN>"
			<< L"<DCDF>" << hz << L"</DCDF>"
			<< L"<DCDV>" << (drv.empty() ? L"UNKNOWN" : drv) << L"</DCDV>"
			<< L"<DCSID>" << (dcsid.empty() ? L"UNKNOWN" : dcsid) << L"</DCSID>\r\n";

		obj->Release();

	}

	// 清理
	pEnumerator->Release();
	return "[DISPLAY]" + wStrToStr(ostr.str()) + "[/DISPLAY]";

}



// 获取 monitor 信息
string queryMonitor() {

	wstringstream ostr;
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) 	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";;

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE, nullptr);
	// 若返回已初始化，可忽略

	IWbemLocator* pLoc = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr) || !pLoc) { CoUninitialize();	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";
	}

	IWbemServices* pSvc = nullptr;
	// 注意：监视器信息在 root\WMI 命名空间
	hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
	if (FAILED(hr) || !pSvc) { pLoc->Release(); CoUninitialize(); 	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]"; }
	// 3) 建议用 CreateInstanceEnum 直接枚举（比 ExecQuery 更稳）
	IEnumWbemClassObject* pEnum = nullptr;
	hr = pSvc->CreateInstanceEnum(_bstr_t(L"WmiMonitorID"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr, &pEnum);

	// 4) 也对 pEnum 设一次 blanket（关键）
	CoSetProxyBlanket(pEnum, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);


	// 获取查询结果
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

	// 清理
	pEnum->Release();
	return "[MONITOR]" + wStrToStr(ostr.str()) + "[/MONITOR]";

}


// 解析 SMBIOS 原始表，找到 Type 1（System Information），提取 UUID 的 16 字节
static bool ExtractUuidFromSMBIOS(const std::vector<uint8_t>& data, std::vector<uint8_t>& uuid16) {
	size_t i = 0;
	while (i + 4 <= data.size()) {
		// 结构头：Type(1) Length(1) Handle(2)
		uint8_t type = data[i + 0];
		uint8_t len = data[i + 1];
		if (len < 4 || i + len > data.size()) break;

		if (type == 1) { // System Information (Type 1)
			// UUID 按规范在 offset 0x08 起 16 字节（SMBIOS 2.6+）
			if (len >= 0x18 && i + 0x08 + 16 <= data.size()) {
				uuid16.assign(data.begin() + i + 0x08, data.begin() + i + 0x08 + 16);
				return true;
			}
		}

		// 跳过格式化区后面跟随的字符串集合，直到遇到双 0 结束
		size_t j = i + len; // 字符串区起点
		while (j + 1 < data.size()) {
			if (data[j] == 0x00 && data[j + 1] == 0x00) { j += 2; break; }
			// 跳过一个以 0 结尾的字符串
			while (j < data.size() && data[j] != 0x00) ++j;
			if (j < data.size() && data[j] == 0x00) ++j;
		}
		i = j;
	}
	return false;
}


// 获取 bios 信息
string querySmbios() {

	std::wstringstream ostr;
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) return "[SMBIOSUUID][/SMBIOSUUID]";

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE, nullptr); // 若已初始化可忽略返回

	IWbemLocator* pLoc = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr) || !pLoc) { CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	// 关键：ROOT\WMI
	IWbemServices* pSvc = nullptr;
	hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
	if (FAILED(hr) || !pSvc) { pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
	if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	IEnumWbemClassObject* pEnum = nullptr;
	// 读取原始 SMBIOS 表
	hr = pSvc->ExecQuery(bstr_t(L"WQL"),
		bstr_t(L"SELECT SMBiosData FROM MSSmBios_RawSMBiosTables"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
	if (FAILED(hr) || !pEnum) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return "[SMBIOSUUID][/SMBIOSUUID]"; }

	// 对枚举器也设一次 blanket（有些环境必要）
	CoSetProxyBlanket(pEnum, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

	IWbemClassObject* obj = nullptr; ULONG ret = 0;
	hr = pEnum->Next(WBEM_INFINITE, 1, &obj, &ret);
	if (FAILED(hr) || ret == 0 || !obj) {
		if (pEnum) pEnum->Release(); pSvc->Release(); pLoc->Release(); CoUninitialize();
		return "[SMBIOSUUID]" + wStrToStr(ostr.str()) + "[/SMBIOSUUID]";
	}

	// 取 SMBiosData（二进制 SAFEARRAY）
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




// 获取 CPU 信息
string GetCPUInfo(IWbemServices* pSvc) {

	HRESULT hres;
	// 查询 CPU 信息
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {

		return  "[SYS]<CSNP>0</CSNP><CSNLP>0</CSNLP>[/SYS][CPU][/CPU]";
	}

	// 获取查询结果
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

	// 清理
	pEnumerator->Release();
	return wStrToStr(sysStr.str());

}


// 根据 PNPDeviceID 回退查询 PhysicalMedia.SerialNumber（某些品牌 DiskDrive.SerialNumber 为空）
static std::wstring QueryPhysicalMediaSerialByPNP(IWbemServices* pSvc, const std::wstring& pnpId) {
	if (pnpId.empty()) return L"";
	// 注意：Win32_PhysicalMedia.Tag 通常与 Win32_DiskDrive.DeviceID 或 PNP 相关，但供应商实现各异
	// 更稳妥做法：直接 SELECT * FROM Win32_PhysicalMedia 然后尝试匹配 SerialNumber 不为空的项
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

	// 查询磁盘的 WMI 查询语句
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

	// 获取磁盘信息
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	std::wstring diskListText;
	while (pEnumerator) {
		IWbemClassObject* obj = nullptr; ULONG ret = 0;
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &obj, &ret);
		if (ret == 0 || !obj) break;

		std::wstring status = GetBstrProp(obj, L"Status");           // "OK" / "Degraded" 等
		bool         loaded = GetBoolProp(obj, L"MediaLoaded", true);// 是否有介质（SSD/HDD 固定介质通常为 true）
		std::wstring did = GetBstrProp(obj, L"DeviceID");         // \\.\PHYSICALDRIVE0
		std::wstring ifType = GetBstrProp(obj, L"InterfaceType");    // "IDE"/"SCSI"/"NVMe"/"USB" 等
		std::wstring model = GetBstrProp(obj, L"Model");            // 型号
		std::wstring fwrev = GetBstrProp(obj, L"FirmwareRevision"); // 固件版本
		std::wstring sn = GetBstrProp(obj, L"SerialNumber");     // 某些厂商可能为空或有空格
		ULONGLONG    size = GetU64Prop(obj, L"Size");              // 字节
		std::wstring pnp = GetBstrProp(obj, L"PNPDeviceID");      // 需要时可输出

		// 去掉序列号的尾部空白
		if (!sn.empty()) {
			while (!sn.empty() && (sn.back() == L' ' || sn.back() == L'\t')) sn.pop_back();
		}
		// 回退：如果 DiskDrive.SerialNumber 为空，用 PhysicalMedia.SerialNumber
		if (sn.empty()) {
			std::wstring alt = QueryPhysicalMediaSerialByPNP(pSvc, pnp);
			if (!alt.empty()) sn = alt;
		}

		// 输出为你的标签格式
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


// 释放资源
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
	//截图桌面
	CaptureDesktop(L"screenshot.bmp");
	//

	ShutdownGDIPlus(0);

}