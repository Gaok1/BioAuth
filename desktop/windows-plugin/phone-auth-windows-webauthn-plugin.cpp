#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <objbase.h>
#include <pluginauthenticator.h>
#include <webauthn.h>
#include <webauthnplugin.h>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Data.Json.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "runtimeobject.lib")
#pragma comment(lib, "windowsapp.lib")

using winrt::Windows::Data::Json::JsonArray;
using winrt::Windows::Data::Json::JsonObject;
using winrt::Windows::Data::Json::JsonValue;

namespace {

constexpr CLSID kPluginClsid =
    {0xd8e846b4, 0xb146, 0x4335, {0xa8, 0x4a, 0xa0, 0x96, 0x91, 0x2e, 0xb0, 0xcb}};
constexpr wchar_t kPluginName[] = L"PhoneAuth";
constexpr wchar_t kPluginRpId[] = L"bioauth.local";
constexpr size_t kMaxMessage = 128 * 1024;

std::atomic<long> g_objects{0};
HANDLE g_idleEvent = nullptr;

std::wstring guid_string(REFGUID guid) {
  wchar_t text[40]{};
  StringFromGUID2(guid, text, static_cast<int>(std::size(text)));
  return text;
}

std::wstring request_id_string(REFGUID guid) {
  auto value = guid_string(guid);
  return value.substr(1, value.size() - 2);
}

std::string base64url(std::span<const uint8_t> bytes) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string result;
  result.reserve((bytes.size() * 4 + 2) / 3);
  uint32_t value = 0;
  int bits = 0;
  for (uint8_t byte : bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      result.push_back(alphabet[(value >> bits) & 63]);
    }
  }
  if (bits) result.push_back(alphabet[(value << (6 - bits)) & 63]);
  return result;
}

std::vector<uint8_t> from_base64url(std::string_view text) {
  auto index = [](char value) -> int {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
  };
  if (text.empty() || text.size() % 4 == 1) throw std::runtime_error("invalid base64url");
  std::vector<uint8_t> output;
  output.reserve(text.size() * 3 / 4);
  uint32_t value = 0;
  int bits = 0;
  for (char character : text) {
    int digit = index(character);
    if (digit < 0) throw std::runtime_error("invalid base64url");
    value = (value << 6) | static_cast<uint32_t>(digit);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push_back(static_cast<uint8_t>(value >> bits));
      value &= (1u << bits) - 1;
    }
  }
  if (value != 0) throw std::runtime_error("non-canonical base64url");
  return output;
}

std::filesystem::path executable_path() {
  std::wstring buffer(32768, L'\0');
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (!size || size == buffer.size()) throw std::runtime_error("cannot locate plugin executable");
  buffer.resize(size);
  return buffer;
}

std::string json_text(const JsonObject& object) {
  return winrt::to_string(object.Stringify());
}

JsonObject call_host(const JsonObject& request) {
  std::string body = json_text(request);
  if (body.empty() || body.size() > kMaxMessage) throw std::runtime_error("plugin request is too large");

  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  HANDLE childInputRead = nullptr, childInputWrite = nullptr;
  HANDLE childOutputRead = nullptr, childOutputWrite = nullptr;
  if (!CreatePipe(&childInputRead, &childInputWrite, &inherit, 0) ||
      !CreatePipe(&childOutputRead, &childOutputWrite, &inherit, 0)) {
    throw std::runtime_error("cannot create native-host pipes");
  }
  auto close = [](HANDLE handle) { if (handle) CloseHandle(handle); };
  SetHandleInformation(childInputWrite, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(childOutputRead, HANDLE_FLAG_INHERIT, 0);

  auto host = executable_path().parent_path() / L"phone-auth-webauthn-host.exe";
  std::wstring command = L"\"" + host.wstring() + L"\"";
  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  startup.hStdInput = childInputRead;
  startup.hStdOutput = childOutputWrite;
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(host.c_str(), command.data(), nullptr, nullptr, TRUE,
                      CREATE_NO_WINDOW, nullptr, host.parent_path().c_str(), &startup, &process)) {
    close(childInputRead); close(childInputWrite); close(childOutputRead); close(childOutputWrite);
    throw std::runtime_error("cannot start PhoneAuth native host");
  }
  close(childInputRead);
  close(childOutputWrite);

  uint32_t length = static_cast<uint32_t>(body.size());
  DWORD written = 0;
  bool sent = WriteFile(childInputWrite, &length, sizeof(length), &written, nullptr) &&
              written == sizeof(length) &&
              WriteFile(childInputWrite, body.data(), length, &written, nullptr) && written == length;
  close(childInputWrite);
  if (!sent) {
    TerminateProcess(process.hProcess, 1);
    close(childOutputRead); close(process.hThread); close(process.hProcess);
    throw std::runtime_error("cannot write to PhoneAuth native host");
  }

  uint32_t responseLength = 0;
  DWORD read = 0;
  if (!ReadFile(childOutputRead, &responseLength, sizeof(responseLength), &read, nullptr) ||
      read != sizeof(responseLength) || !responseLength || responseLength > kMaxMessage) {
    close(childOutputRead); close(process.hThread); close(process.hProcess);
    throw std::runtime_error("PhoneAuth native host returned no response");
  }
  std::string response(responseLength, '\0');
  size_t offset = 0;
  while (offset < response.size()) {
    if (!ReadFile(childOutputRead, response.data() + offset,
                  static_cast<DWORD>(response.size() - offset), &read, nullptr) || !read) {
      close(childOutputRead); close(process.hThread); close(process.hProcess);
      throw std::runtime_error("PhoneAuth native host response was truncated");
    }
    offset += read;
  }
  close(childOutputRead);
  WaitForSingleObject(process.hProcess, 5000);
  close(process.hThread);
  close(process.hProcess);
  return JsonObject::Parse(winrt::to_hstring(response));
}

class PluginApi {
 public:
  PluginApi() {
    module_ = LoadLibraryExW(L"WebAuthnPlugin.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module_) throw std::runtime_error(
        "Windows WebAuthn plugin API is unavailable; a fully updated Windows 11 24H2 or newer is required");
  }
  ~PluginApi() { if (module_) FreeLibrary(module_); }
  template <typename T> T get(const char* name) const {
    auto address = GetProcAddress(module_, name);
    if (!address) throw std::runtime_error(std::string("Windows WebAuthn plugin API is missing ") + name);
    return reinterpret_cast<T>(address);
  }
 private:
  HMODULE module_{};
};

HRESULT verify_request(const WEBAUTHN_PLUGIN_OPERATION_REQUEST& request) {
  try {
    PluginApi api;
    auto getKey = api.get<decltype(&WebAuthNPluginGetOperationSigningPublicKey)>(
        "WebAuthNPluginGetOperationSigningPublicKey");
    auto freeKey = api.get<decltype(&WebAuthNPluginFreePublicKeyResponse)>(
        "WebAuthNPluginFreePublicKeyResponse");
    DWORD keySize = 0;
    PBYTE keyBytes = nullptr;
    HRESULT hr = getKey(kPluginClsid, &keySize, &keyBytes);
    if (FAILED(hr)) return hr;
    struct FreeKey { decltype(freeKey) fn; PBYTE value; ~FreeKey() { fn(value); } } free{freeKey, keyBytes};
    if (!keyBytes || keySize < sizeof(BCRYPT_KEY_BLOB) || !request.pbRequestSignature ||
        !request.cbRequestSignature || !request.pbEncodedRequest || !request.cbEncodedRequest) return E_INVALIDARG;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hashSize = 0, copied = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return E_FAIL;
    auto closeAlgorithm = [&] { BCryptCloseAlgorithmProvider(algorithm, 0); };
    if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
                          sizeof(hashSize), &copied, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
      closeAlgorithm(); return E_FAIL;
    }
    std::vector<uint8_t> digest(hashSize);
    NTSTATUS status = BCryptHashData(hash, request.pbEncodedRequest, request.cbEncodedRequest, 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), hashSize, 0);
    BCryptDestroyHash(hash);
    closeAlgorithm();
    if (status < 0) return E_FAIL;

    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (FAILED(NCryptOpenStorageProvider(&provider, nullptr, 0))) return E_FAIL;
    hr = NCryptImportKey(provider, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, &key,
                         keyBytes, keySize, 0);
    if (SUCCEEDED(hr)) {
      auto header = reinterpret_cast<const BCRYPT_KEY_BLOB*>(keyBytes);
      BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
      void* paddingPointer = header->Magic == BCRYPT_RSAPUBLIC_MAGIC ? &padding : nullptr;
      DWORD flags = header->Magic == BCRYPT_RSAPUBLIC_MAGIC ? BCRYPT_PAD_PKCS1 : 0;
      hr = NCryptVerifySignature(key, paddingPointer, digest.data(), hashSize,
                                request.pbRequestSignature, request.cbRequestSignature, flags);
    }
    if (key) NCryptFreeObject(key);
    NCryptFreeObject(provider);
    return hr;
  } catch (...) {
    return E_FAIL;
  }
}

void add_descriptors(JsonArray& output, const WEBAUTHN_CREDENTIAL_LIST& list) {
  if (!list.ppCredentials) return;
  for (DWORD index = 0; index < list.cCredentials; ++index) {
    auto credential = list.ppCredentials[index];
    if (!credential || !credential->pbId || !credential->cbId) continue;
    JsonObject descriptor;
    descriptor.SetNamedValue(L"type", JsonValue::CreateStringValue(L"public-key"));
    descriptor.SetNamedValue(L"id", JsonValue::CreateStringValue(winrt::to_hstring(
        base64url({credential->pbId, credential->cbId}))));
    output.Append(descriptor);
  }
}

JsonObject relay_request(std::wstring_view operation, std::wstring_view rpId,
                         const JsonObject& options, REFGUID transactionId) {
  JsonObject request;
  request.SetNamedValue(L"operation", JsonValue::CreateStringValue(operation));
  request.SetNamedValue(L"requestId", JsonValue::CreateStringValue(request_id_string(transactionId)));
  request.SetNamedValue(L"origin", JsonValue::CreateStringValue(L"https://" + std::wstring(rpId)));
  request.SetNamedValue(L"options", options);
  JsonObject answer = call_host(request);
  if (!answer.GetNamedBoolean(L"ok", false)) {
    throw std::runtime_error(winrt::to_string(answer.GetNamedString(L"error", L"PhoneAuth refused the passkey request")));
  }
  return answer.GetNamedObject(L"response");
}

class Plugin final : public IPluginAuthenticator {
 public:
  Plugin() { ++g_objects; ResetEvent(g_idleEvent); }
  ~Plugin() { if (--g_objects == 0) SetEvent(g_idleEvent); }

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
    if (!value) return E_POINTER;
    *value = nullptr;
    if (iid == __uuidof(IUnknown) || iid == __uuidof(IPluginAuthenticator)) {
      *value = static_cast<IPluginAuthenticator*>(this);
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG remaining = --references_;
    if (!remaining) delete this;
    return remaining;
  }

  HRESULT STDMETHODCALLTYPE MakeCredential(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
                                           PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
    if (!request || !response) return E_INVALIDARG;
    *response = {};
    if (request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR) return NTE_NOT_SUPPORTED;
    HRESULT verified = verify_request(*request);
    if (FAILED(verified)) return verified;
    try {
      PluginApi api;
      auto decode = api.get<decltype(&WebAuthNDecodeMakeCredentialRequest)>("WebAuthNDecodeMakeCredentialRequest");
      auto release = api.get<decltype(&WebAuthNFreeDecodedMakeCredentialRequest)>("WebAuthNFreeDecodedMakeCredentialRequest");
      auto encode = api.get<decltype(&WebAuthNEncodeMakeCredentialResponse)>("WebAuthNEncodeMakeCredentialResponse");
      PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST decoded = nullptr;
      HRESULT hr = decode(request->cbEncodedRequest, request->pbEncodedRequest, &decoded);
      if (FAILED(hr)) return hr;
      struct Free { decltype(release) fn; PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST value; ~Free(){ fn(value); } } free{release, decoded};
      if (!decoded->pRpInformation || !decoded->pUserInformation ||
          !decoded->pRpInformation->pwszId || !decoded->pRpInformation->pwszName ||
          !decoded->pUserInformation->pbId || !decoded->pUserInformation->cbId ||
          !decoded->pUserInformation->pwszName || !decoded->pUserInformation->pwszDisplayName ||
          decoded->cbClientDataHash != 32 || !decoded->pbClientDataHash) return E_INVALIDARG;
      if (decoded->WebAuthNCredentialParameters.cCredentialParameters &&
          !decoded->WebAuthNCredentialParameters.pCredentialParameters) return E_INVALIDARG;
      bool permitsEs256 = false;
      for (DWORD index = 0; index < decoded->WebAuthNCredentialParameters.cCredentialParameters; ++index) {
        const auto& parameter = decoded->WebAuthNCredentialParameters.pCredentialParameters[index];
        permitsEs256 |= parameter.lAlg == WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 &&
                        parameter.pwszCredentialType &&
                        wcscmp(parameter.pwszCredentialType, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY) == 0;
      }
      if (!permitsEs256) return NTE_NOT_SUPPORTED;

      JsonObject options, rp, user, selection;
      rp.SetNamedValue(L"id", JsonValue::CreateStringValue(decoded->pRpInformation->pwszId));
      rp.SetNamedValue(L"name", JsonValue::CreateStringValue(decoded->pRpInformation->pwszName));
      user.SetNamedValue(L"id", JsonValue::CreateStringValue(winrt::to_hstring(base64url(
          {decoded->pUserInformation->pbId, decoded->pUserInformation->cbId}))));
      user.SetNamedValue(L"name", JsonValue::CreateStringValue(decoded->pUserInformation->pwszName));
      user.SetNamedValue(L"displayName", JsonValue::CreateStringValue(decoded->pUserInformation->pwszDisplayName));
      options.SetNamedValue(L"rp", rp);
      options.SetNamedValue(L"user", user);
      options.SetNamedValue(L"challenge", JsonValue::CreateStringValue(
          L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
      JsonArray parameters;
      JsonObject es256;
      es256.SetNamedValue(L"type", JsonValue::CreateStringValue(L"public-key"));
      es256.SetNamedValue(L"alg", JsonValue::CreateNumberValue(-7));
      parameters.Append(es256);
      options.SetNamedValue(L"pubKeyCredParams", parameters);
      selection.SetNamedValue(L"residentKey", JsonValue::CreateStringValue(L"required"));
      selection.SetNamedValue(L"userVerification", JsonValue::CreateStringValue(L"required"));
      options.SetNamedValue(L"authenticatorSelection", selection);
      JsonArray excluded;
      add_descriptors(excluded, decoded->CredentialList);
      if (excluded.Size()) options.SetNamedValue(L"excludeCredentials", excluded);
      options.SetNamedValue(L"clientDataHash", JsonValue::CreateStringValue(winrt::to_hstring(
          base64url({decoded->pbClientDataHash, decoded->cbClientDataHash}))));
      options.SetNamedValue(L"returnAuthenticatorData", JsonValue::CreateBooleanValue(true));

      JsonObject answer = relay_request(L"create", decoded->pRpInformation->pwszId, options, request->transactionId);
      JsonObject fields = answer.GetNamedObject(L"response");
      auto credentialId = from_base64url(winrt::to_string(answer.GetNamedString(L"rawId")));
      auto authenticatorData = from_base64url(winrt::to_string(fields.GetNamedString(L"authenticatorData")));
      WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS details{
          static_cast<DWORD>(credentialId.size()), credentialId.data(),
          decoded->pRpInformation->pwszId, decoded->pRpInformation->pwszName,
          decoded->pUserInformation->cbId, decoded->pUserInformation->pbId,
          decoded->pUserInformation->pwszName, decoded->pUserInformation->pwszDisplayName};
      // The passkey is already committed on the phone. Cache failure must not
      // turn that into an RP-side failure and an orphan; ordinary WebAuthn
      // remains available and a later registration refreshes the cache.
      try {
        auto addCredential = api.get<decltype(&WebAuthNPluginAuthenticatorAddCredentials)>(
            "WebAuthNPluginAuthenticatorAddCredentials");
        addCredential(kPluginClsid, 1, &details);
      } catch (...) {}
      WEBAUTHN_CREDENTIAL_ATTESTATION attestation{};
      attestation.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
      attestation.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
      attestation.cbAuthenticatorData = static_cast<DWORD>(authenticatorData.size());
      attestation.pbAuthenticatorData = authenticatorData.data();
      return encode(&attestation, &response->cbEncodedResponse, &response->pbEncodedResponse);
    } catch (...) {
      return winrt::to_hresult();
    }
  }

  HRESULT STDMETHODCALLTYPE GetAssertion(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
                                         PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
    if (!request || !response) return E_INVALIDARG;
    *response = {};
    if (request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR) return NTE_NOT_SUPPORTED;
    HRESULT verified = verify_request(*request);
    if (FAILED(verified)) return verified;
    try {
      PluginApi api;
      auto decode = api.get<decltype(&WebAuthNDecodeGetAssertionRequest)>("WebAuthNDecodeGetAssertionRequest");
      auto release = api.get<decltype(&WebAuthNFreeDecodedGetAssertionRequest)>("WebAuthNFreeDecodedGetAssertionRequest");
      auto encode = api.get<decltype(&WebAuthNEncodeGetAssertionResponse)>("WebAuthNEncodeGetAssertionResponse");
      PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST decoded = nullptr;
      HRESULT hr = decode(request->cbEncodedRequest, request->pbEncodedRequest, &decoded);
      if (FAILED(hr)) return hr;
      struct Free { decltype(release) fn; PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST value; ~Free(){ fn(value); } } free{release, decoded};
      if (!decoded->pwszRpId || decoded->cbClientDataHash != 32 ||
          !decoded->pbClientDataHash) return E_INVALIDARG;

      JsonObject options;
      options.SetNamedValue(L"rpId", JsonValue::CreateStringValue(decoded->pwszRpId));
      options.SetNamedValue(L"challenge", JsonValue::CreateStringValue(
          L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
      options.SetNamedValue(L"userVerification", JsonValue::CreateStringValue(L"required"));
      options.SetNamedValue(L"clientDataHash", JsonValue::CreateStringValue(winrt::to_hstring(
          base64url({decoded->pbClientDataHash, decoded->cbClientDataHash}))));
      JsonArray allowed;
      add_descriptors(allowed, decoded->CredentialList);
      if (allowed.Size()) options.SetNamedValue(L"allowCredentials", allowed);

      JsonObject answer = relay_request(L"get", decoded->pwszRpId, options, request->transactionId);
      JsonObject fields = answer.GetNamedObject(L"response");
      auto credentialId = from_base64url(winrt::to_string(answer.GetNamedString(L"rawId")));
      auto authenticatorData = from_base64url(winrt::to_string(fields.GetNamedString(L"authenticatorData")));
      auto signature = from_base64url(winrt::to_string(fields.GetNamedString(L"signature")));
      auto userHandle = from_base64url(winrt::to_string(fields.GetNamedString(L"userHandle")));

      WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE assertion{};
      assertion.WebAuthNAssertion.dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;
      assertion.WebAuthNAssertion.Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
      assertion.WebAuthNAssertion.Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
      assertion.WebAuthNAssertion.Credential.cbId = static_cast<DWORD>(credentialId.size());
      assertion.WebAuthNAssertion.Credential.pbId = credentialId.data();
      assertion.WebAuthNAssertion.cbAuthenticatorData = static_cast<DWORD>(authenticatorData.size());
      assertion.WebAuthNAssertion.pbAuthenticatorData = authenticatorData.data();
      assertion.WebAuthNAssertion.cbSignature = static_cast<DWORD>(signature.size());
      assertion.WebAuthNAssertion.pbSignature = signature.data();
      assertion.WebAuthNAssertion.cbUserId = static_cast<DWORD>(userHandle.size());
      assertion.WebAuthNAssertion.pbUserId = userHandle.data();
      WEBAUTHN_USER_ENTITY_INFORMATION user{};
      user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
      user.cbId = static_cast<DWORD>(userHandle.size());
      user.pbId = userHandle.data();
      assertion.pUserInformation = &user;
      assertion.dwNumberOfCredentials = 1;
      assertion.lUserSelected = 1;
      return encode(&assertion, &response->cbEncodedResponse, &response->pbEncodedResponse);
    } catch (...) {
      return winrt::to_hresult();
    }
  }

  HRESULT STDMETHODCALLTYPE CancelOperation(PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) override {
    if (!request) return E_INVALIDARG;
    try {
      JsonObject message;
      message.SetNamedValue(L"operation", JsonValue::CreateStringValue(L"cancel"));
      message.SetNamedValue(L"requestId", JsonValue::CreateStringValue(request_id_string(request->transactionId)));
      call_host(message);
      return S_OK;
    } catch (...) {
      return winrt::to_hresult();
    }
  }

  HRESULT STDMETHODCALLTYPE GetLockStatus(PLUGIN_LOCK_STATUS* status) noexcept override {
    if (!status) return E_POINTER;
    *status = PluginUnlocked;
    return S_OK;
  }
 private:
  std::atomic<ULONG> references_{1};
};

class Factory final : public IClassFactory {
 public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
    if (!value) return E_POINTER;
    *value = nullptr;
    if (iid == __uuidof(IUnknown) || iid == __uuidof(IClassFactory)) {
      *value = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG remaining = --references_; if (!remaining) delete this; return remaining;
  }
  HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** value) override {
    if (outer) return CLASS_E_NOAGGREGATION;
    auto plugin = new (std::nothrow) Plugin();
    if (!plugin) return E_OUTOFMEMORY;
    HRESULT hr = plugin->QueryInterface(iid, value);
    plugin->Release();
    return hr;
  }
  HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
    if (lock) { ++g_objects; ResetEvent(g_idleEvent); }
    else if (--g_objects == 0) SetEvent(g_idleEvent);
    return S_OK;
  }
 private:
  std::atomic<ULONG> references_{1};
};

std::vector<uint8_t> authenticator_info() {
  // {1:["FIDO_2_0","FIDO_2_1"],3:AAGUID,4:{"rk":true,"up":true,"uv":true},
  //  9:["internal"],10:[{"alg":-7,"type":"public-key"}]}
  static constexpr char hex[] =
      "A50182684649444F5F325F30684649444F5F325F31035000000000000000000000000000000000"
      "04A362726BF5627570F5627576F5098168696E7465726E616C"
      "0A81A263616C672664747970656A7075626C69632D6B6579";
  std::vector<uint8_t> bytes;
  bytes.reserve((sizeof(hex) - 1) / 2);
  auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'A' + 10; };
  for (size_t i = 0; i < sizeof(hex) - 1; i += 2) bytes.push_back(
      static_cast<uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
  return bytes;
}

HRESULT write_com_registration(bool install) {
  std::wstring keyPath = L"Software\\Classes\\CLSID\\" + guid_string(kPluginClsid) + L"\\LocalServer32";
  if (!install) {
    std::wstring parent = L"Software\\Classes\\CLSID\\" + guid_string(kPluginClsid);
    LONG result = RegDeleteTreeW(HKEY_CURRENT_USER, parent.c_str());
    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND
        ? S_OK : HRESULT_FROM_WIN32(result);
  }
  HKEY key = nullptr;
  LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, nullptr, 0,
                                KEY_SET_VALUE, nullptr, &key, nullptr);
  if (result != ERROR_SUCCESS) return HRESULT_FROM_WIN32(result);
  std::wstring command = L"\"" + executable_path().wstring() + L"\" --server";
  result = RegSetValueExW(key, nullptr, 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(command.c_str()),
                         static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
  if (result != ERROR_SUCCESS) write_com_registration(false);
  return HRESULT_FROM_WIN32(result);
}

HRESULT register_plugin(bool install) {
  if (!install) {
    HRESULT platformResult = S_OK;
    try {
      PluginApi api;
      auto remove = api.get<decltype(&WebAuthNPluginRemoveAuthenticator)>(
          "WebAuthNPluginRemoveAuthenticator");
      platformResult = remove(kPluginClsid);
    } catch (...) {
      platformResult = winrt::to_hresult();
    }
    HRESULT registryResult = write_com_registration(false);
    if (FAILED(registryResult)) return registryResult;
    return platformResult == NTE_NOT_FOUND ? S_OK : platformResult;
  }
  PluginApi api;
  auto remove = api.get<decltype(&WebAuthNPluginRemoveAuthenticator)>("WebAuthNPluginRemoveAuthenticator");
  auto add = api.get<decltype(&WebAuthNPluginAddAuthenticator)>("WebAuthNPluginAddAuthenticator");
  auto freeResponse = api.get<decltype(&WebAuthNPluginFreeAddAuthenticatorResponse)>(
      "WebAuthNPluginFreeAddAuthenticatorResponse");
  HRESULT hr = write_com_registration(true);
  if (FAILED(hr)) return hr;
  remove(kPluginClsid);
  auto info = authenticator_info();
  WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS options{
      kPluginName, kPluginClsid, kPluginRpId, nullptr, nullptr,
      static_cast<DWORD>(info.size()), info.data(), 0, nullptr};
  PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE response = nullptr;
  hr = add(&options, &response);
  if (response) freeResponse(response);
  if (FAILED(hr)) write_com_registration(false);
  return hr;
}

HRESULT run_server() {
  g_idleEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_idleEvent) return HRESULT_FROM_WIN32(GetLastError());
  auto factory = new (std::nothrow) Factory();
  if (!factory) return E_OUTOFMEMORY;
  DWORD cookie = 0;
  HRESULT hr = CoRegisterClassObject(kPluginClsid, factory, CLSCTX_LOCAL_SERVER,
                                     REGCLS_MULTIPLEUSE, &cookie);
  factory->Release();
  if (FAILED(hr)) return hr;
  // Remain available while Windows owns an authenticator object, then leave
  // after five quiet minutes. COM starts a fresh server for the next request.
  do { WaitForSingleObject(g_idleEvent, 5 * 60 * 1000); } while (g_objects.load() != 0);
  CoRevokeClassObject(cookie);
  CloseHandle(g_idleEvent);
  g_idleEvent = nullptr;
  return S_OK;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  winrt::init_apartment(winrt::apartment_type::multi_threaded);
  try {
    if (argc > 1 && std::wstring_view(argv[1]) == L"--self-test") {
      const std::vector<uint8_t> sample{0, 1, 2, 253, 254, 255};
      return from_base64url(base64url(sample)) == sample && authenticator_info().size() > 32 ? 0 : 1;
    }
    HRESULT hr = argc > 1 && std::wstring_view(argv[1]) == L"--register"
        ? register_plugin(true)
        : argc > 1 && std::wstring_view(argv[1]) == L"--unregister"
            ? register_plugin(false)
            : run_server();
    if (FAILED(hr)) {
      std::wcerr << L"PhoneAuth Windows passkey plugin failed: 0x" << std::hex << hr << L"\n";
      return 1;
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "PhoneAuth Windows passkey plugin failed: " << error.what() << "\n";
    return 1;
  }
}
