#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kMaxHeaderBytes = 1024 * 1024;
constexpr std::size_t kMaxBodyBytes = 512ULL * 1024ULL * 1024ULL;
constexpr DWORD kInitialClientTimeoutMs = 60000;
constexpr DWORD kReusedClientTimeoutMs = 30000;
constexpr DWORD kClientSendTimeoutMs = 60000;
constexpr long kConnectTimeoutMs = 10000;
constexpr long kAutoHttp3ConnectTimeoutMs = 3000;
constexpr long kLowSpeedTimeSeconds = 60;
constexpr const char* kHttpsMethodMarker = "\x01";

struct Header {
    std::string name;
    std::string value;
};

struct Request {
    std::string method;
    std::string target;
    std::string protocol;
    std::vector<Header> headers;
    std::string body;
    bool plain_http = false;
};

struct Config {
    std::string listen_address = "127.0.0.1";
    unsigned short port = 0;
    std::string profile = "chrome150";
    std::string http_version = "auto";
    unsigned int workers = 32;
};

std::atomic<bool> g_running{true};
SOCKET g_listener = INVALID_SOCKET;
SOCKET g_wake_sender = INVALID_SOCKET;
std::mutex g_log_mutex;

void wake_dispatcher() {
    if (g_wake_sender == INVALID_SOCKET) return;
    const char byte = 1;
    send(g_wake_sender, &byte, 1, 0);
}

bool create_wake_sockets(SOCKET& receiver, SOCKET& sender) {
    receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver == INVALID_SOCKET || sender == INVALID_SOCKET) return false;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(receiver, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        return false;
    }

    int address_size = sizeof(address);
    if (getsockname(receiver, reinterpret_cast<sockaddr*>(&address), &address_size) == SOCKET_ERROR ||
        connect(sender, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        return false;
    }

    u_long nonblocking = 1;
    return ioctlsocket(receiver, FIONBIO, &nonblocking) != SOCKET_ERROR &&
           ioctlsocket(sender, FIONBIO, &nonblocking) != SOCKET_ERROR;
}

void drain_wake_socket(SOCKET receiver) {
    char buffer[64];
    while (recv(receiver, buffer, sizeof(buffer), 0) > 0) {
    }
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

const std::string* find_header(const std::vector<Header>& headers, const std::string& wanted) {
    for (const auto& header : headers) {
        if (lower(header.name) == wanted) return &header.value;
    }
    return nullptr;
}

bool recv_more(SOCKET socket, std::string& buffer) {
    char chunk[16384];
    const int received = recv(socket, chunk, static_cast<int>(sizeof(chunk)), 0);
    if (received <= 0) return false;
    buffer.append(chunk, received);
    return true;
}

bool send_all(SOCKET socket, const char* data, std::size_t size);

void enable_abortive_close(SOCKET socket) {
    linger option{};
    option.l_onoff = 1;
    option.l_linger = 0;

    setsockopt(
        socket,
        SOL_SOCKET,
        SO_LINGER,
        reinterpret_cast<const char*>(&option),
        sizeof(option)
    );
}

bool read_chunked_body(SOCKET socket, std::string& pending, std::string& body, std::string& error) {
    while (true) {
        std::size_t line_end = pending.find("\r\n");
        while (line_end == std::string::npos) {
            if (!recv_more(socket, pending)) {
                error = "connection closed inside chunk size";
                return false;
            }
            line_end = pending.find("\r\n");
        }

        std::string size_text = pending.substr(0, line_end);
        pending.erase(0, line_end + 2);
        const auto extension = size_text.find(';');
        if (extension != std::string::npos) size_text.resize(extension);

        errno = 0;
        char* end = nullptr;
        const unsigned long long chunk_size = std::strtoull(size_text.c_str(), &end, 16);
        if (errno != 0 || end == size_text.c_str() || *end != '\0') {
            error = "invalid chunk size";
            return false;
        }
        if (chunk_size > kMaxBodyBytes || body.size() + chunk_size > kMaxBodyBytes) {
            error = "request body is too large";
            return false;
        }

        if (chunk_size == 0) {
            while (true) {
                std::size_t trailer_end = pending.find("\r\n");
                while (trailer_end == std::string::npos) {
                    if (!recv_more(socket, pending)) {
                        error = "connection closed inside chunk trailers";
                        return false;
                    }
                    trailer_end = pending.find("\r\n");
                }
                const bool trailers_complete = trailer_end == 0;
                pending.erase(0, trailer_end + 2);
                if (trailers_complete) return true;
            }
        }
        while (pending.size() < chunk_size + 2) {
            if (!recv_more(socket, pending)) {
                error = "connection closed inside chunk data";
                return false;
            }
        }
        if (pending[chunk_size] != '\r' || pending[chunk_size + 1] != '\n') {
            error = "invalid chunk terminator";
            return false;
        }
        body.append(pending.data(), static_cast<std::size_t>(chunk_size));
        pending.erase(0, static_cast<std::size_t>(chunk_size) + 2);
    }
}

bool read_request(SOCKET socket, std::string& pending, Request& request, std::string& error) {
    std::size_t header_end = std::string::npos;
    while ((header_end = pending.find("\r\n\r\n")) == std::string::npos) {
        if (pending.size() >= kMaxHeaderBytes) {
            error = "request headers are too large";
            return false;
        }
        if (!recv_more(socket, pending)) {
            if (!pending.empty()) error = "connection closed before request headers";
            return false;
        }
    }

    std::istringstream stream(pending.substr(0, header_end));
    std::string line;
    if (!std::getline(stream, line)) {
        error = "missing request line";
        return false;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();

    std::istringstream request_line(line);
    if (!(request_line >> request.method >> request.target >> request.protocol)) {
        error = "invalid request line";
        return false;
    }

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        request.headers.push_back({trim(line.substr(0, colon)), trim(line.substr(colon + 1))});
    }

    pending.erase(0, header_end + 4);
    const std::string* expect = find_header(request.headers, "expect");
    const bool expects_continue = expect &&
        lower(*expect).find("100-continue") != std::string::npos;
    const std::string* transfer_encoding = find_header(request.headers, "transfer-encoding");
    if (transfer_encoding && lower(*transfer_encoding).find("chunked") != std::string::npos) {
        if (expects_continue && !send_all(socket, "HTTP/1.1 100 Continue\r\n\r\n", 25)) {
            error = "failed to send 100 Continue";
            return false;
        }
        return read_chunked_body(socket, pending, request.body, error);
    }

    std::size_t content_length = 0;
    if (const std::string* value = find_header(request.headers, "content-length")) {
        errno = 0;
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(value->c_str(), &end, 10);
        if (errno != 0 || end == value->c_str() || *end != '\0' || parsed > kMaxBodyBytes) {
            error = "invalid Content-Length";
            return false;
        }
        content_length = static_cast<std::size_t>(parsed);
    }

    if (content_length > 0 && expects_continue &&
        !send_all(socket, "HTTP/1.1 100 Continue\r\n\r\n", 25)) {
        error = "failed to send 100 Continue";
        return false;
    }

    while (pending.size() < content_length) {
        if (!recv_more(socket, pending)) {
            error = "connection closed inside request body";
            return false;
        }
    }
    request.body.assign(pending.data(), content_length);
    pending.erase(0, content_length);
    return true;
}

bool request_wants_keep_alive(const Request& request) {
    const std::string* connection = find_header(request.headers, "connection");
    if (!connection) connection = find_header(request.headers, "proxy-connection");
    const std::string value = connection ? lower(*connection) : std::string();
    if (value.find("close") != std::string::npos) return false;
    if (request.protocol == "HTTP/1.0") return value.find("keep-alive") != std::string::npos;
    return true;
}

bool send_all(SOCKET socket, const char* data, std::size_t size) {
    while (size > 0) {
        const int sent = send(socket, data, static_cast<int>(std::min<std::size_t>(size, INT_MAX)), 0);
        if (sent <= 0) return false;
        data += sent;
        size -= sent;
    }
    return true;
}

std::string reason_phrase(long status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 413: return "Content Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "Status";
    }
}

bool is_hop_by_hop(const std::string& name) {
    const std::string normalized = lower(name);
    return normalized == "connection" || normalized == "keep-alive" ||
           normalized == "proxy-authenticate" || normalized == "proxy-authorization" ||
           normalized == "proxy-connection" || normalized == "te" ||
           normalized == "trailer" || normalized == "transfer-encoding" ||
           normalized == "upgrade";
}

void send_text_response(SOCKET socket, long status, const std::string& text) {
    std::ostringstream head;
    head << "HTTP/1.1 " << status << ' ' << reason_phrase(status) << "\r\n"
         << "Content-Type: text/plain; charset=utf-8\r\n"
         << "Content-Length: " << text.size() << "\r\n";
    head << "Connection: close\r\n\r\n";
    const std::string serialized = head.str();
    send_all(socket, serialized.data(), serialized.size());
    if (!text.empty()) send_all(socket, text.data(), text.size());
}

struct CurlResponseState {
    SOCKET client = INVALID_SOCKET;
    long status = 0;
    std::vector<Header> headers;
    std::string negotiated_http;
    bool head_request = false;
    bool headers_sent = false;
    bool chunked = false;
    bool keep_alive = false;
    bool send_failed = false;
};

bool send_stream_headers(CurlResponseState& state) {
    if (state.headers_sent) return true;

    std::ostringstream head;
    bool has_content_length = false;
    const bool body_allowed = !state.head_request && state.status != 204 && state.status != 304;
    head << "HTTP/1.1 " << state.status << ' ' << reason_phrase(state.status) << "\r\n";
    for (const auto& header : state.headers) {
        const std::string name = lower(header.name);
        if (name == "content-encoding" || name == "x-proxy-decoded-content-encoding") continue;
        if (name == "content-length") {
            if (state.head_request) {
                head << header.name << ": " << header.value << "\r\n";
                has_content_length = true;
            }
            continue;
        }
        if (is_hop_by_hop(name) || name == "x-proxy-upstream-http") continue;
        head << header.name << ": " << header.value << "\r\n";
    }
    if (!state.negotiated_http.empty()) {
        head << "X-Proxy-Upstream-Http: " << state.negotiated_http << "\r\n";
    }
    if (body_allowed) {
        head << "Transfer-Encoding: chunked\r\n";
        state.chunked = true;
    } else if (state.head_request && !has_content_length) {
        head << "Content-Length: 0\r\n";
    }
    head << "Connection: " << (state.keep_alive ? "keep-alive" : "close") << "\r\n\r\n";

    const std::string serialized = head.str();
    state.headers_sent = send_all(state.client, serialized.data(), serialized.size());
    state.send_failed = !state.headers_sent;
    return state.headers_sent;
}

std::size_t on_curl_body(char* data, std::size_t size, std::size_t count, void* userdata) {
    const std::size_t bytes = size * count;
    auto* state = static_cast<CurlResponseState*>(userdata);
    if (!send_stream_headers(*state)) return 0;
    if (bytes == 0 || !state->chunked) return bytes;

    std::ostringstream prefix;
    prefix << std::hex << bytes << "\r\n";
    const std::string serialized_prefix = prefix.str();
    if (!send_all(state->client, serialized_prefix.data(), serialized_prefix.size()) ||
        !send_all(state->client, data, bytes) || !send_all(state->client, "\r\n", 2)) {
        state->send_failed = true;
        return 0;
    }
    return bytes;
}

std::size_t on_curl_header(char* data, std::size_t size, std::size_t count, void* userdata) {
    const std::size_t bytes = size * count;
    std::string line(data, bytes);
    auto* state = static_cast<CurlResponseState*>(userdata);
    if (line.rfind("HTTP/", 0) == 0) {
        state->headers.clear();
        std::istringstream status_line(trim(line));
        std::string protocol;
        status_line >> protocol >> state->status;
        if (protocol == "HTTP/3") state->negotiated_http = "h3";
        else if (protocol == "HTTP/2") state->negotiated_http = "h2";
        else if (protocol == "HTTP/1.1") state->negotiated_http = "http/1.1";
        else if (protocol == "HTTP/1.0") state->negotiated_http = "http/1.0";
        return bytes;
    }
    if (line == "\r\n") {
        if (state->status >= 200 && !send_stream_headers(*state)) return 0;
        return bytes;
    }
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
        Header header{trim(line.substr(0, colon)), trim(line.substr(colon + 1))};
        state->headers.push_back(std::move(header));
    }
    return bytes;
}

std::string curl_http_name(long version) {
    switch (version) {
        case CURL_HTTP_VERSION_1_0: return "http/1.0";
        case CURL_HTTP_VERSION_1_1: return "http/1.1";
        case CURL_HTTP_VERSION_2_0: return "h2";
        case CURL_HTTP_VERSION_3: return "h3";
        default: return "unknown";
    }
}

bool should_forward_request_header(const std::string& name) {
    const std::string normalized = lower(name);
    return normalized != "host" && normalized != "content-length" &&
           normalized != "accept-encoding" && normalized != "expect" &&
           !is_hop_by_hop(normalized);
}

struct TransferResult {
    long status = 502;
    std::string negotiated_http;
    std::string error;
    bool response_started = false;
    CURLcode curl_code = CURLE_OK;
};

struct CurlShareState {
    CURLSH* handle = nullptr;
    std::array<std::mutex, CURL_LOCK_DATA_LAST> locks;
};

void lock_curl_share(CURL*, curl_lock_data data, curl_lock_access, void* user_data) {
    auto* state = static_cast<CurlShareState*>(user_data);
    state->locks[static_cast<std::size_t>(data)].lock();
}

void unlock_curl_share(CURL*, curl_lock_data data, void* user_data) {
    auto* state = static_cast<CurlShareState*>(user_data);
    state->locks[static_cast<std::size_t>(data)].unlock();
}

struct CurlWorker {
    CURL* easy = nullptr;
    CURLSH* share = nullptr;

    explicit CurlWorker(CURLSH* shared) : share(shared) {}

    ~CurlWorker() {
        if (easy) curl_easy_cleanup(easy);
    }
};

int abort_curl_on_shutdown(void*, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return g_running ? 0 : 1;
}

TransferResult perform_request_once(CurlWorker& worker, const Request& request, const Config& config,
                                    const std::string& url, SOCKET client, long requested_version,
                                    long connect_timeout_ms) {
    TransferResult result;

    if (!worker.easy) {
        worker.easy = curl_easy_init();
    } else {
        curl_easy_reset(worker.easy);
    }
    if (!worker.easy) {
        result.error = "curl_easy_init failed";
        return result;
    }

    CURLcode code = curl_easy_impersonate(worker.easy, config.profile.c_str(), 1);
    if (code != CURLE_OK) {
        result.error = "Unknown or invalid impersonation profile: " + config.profile;
        return result;
    }

    curl_slist* request_headers = nullptr;
    for (const auto& header : request.headers) {
        if (!should_forward_request_header(header.name)) continue;
        const std::string serialized = header.name + ": " + header.value;
        request_headers = curl_slist_append(request_headers, serialized.c_str());
    }
    request_headers = curl_slist_append(request_headers, "Expect:");

    CurlResponseState state;
    state.client = client;
    state.head_request = lower(request.method) == "head";
    state.keep_alive = request_wants_keep_alive(request);
    char error_buffer[CURL_ERROR_SIZE] = {};
    CURL* curl = worker.easy;
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_SHARE, worker.share);
    curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, requested_version);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, kLowSpeedTimeSeconds);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, abort_curl_on_shutdown);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_curl_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_curl_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &state);

    if (state.head_request) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (!request.body.empty() || find_header(request.headers, "content-length")) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         static_cast<curl_off_t>(request.body.size()));
    }

    code = curl_easy_perform(curl);
    curl_slist_free_all(request_headers);
    result.curl_code = code;
    result.response_started = state.headers_sent;
    result.status = state.status > 0 ? state.status : 502;
    result.negotiated_http = state.negotiated_http;
    if (code != CURLE_OK) {
        result.error = error_buffer[0] ? error_buffer : curl_easy_strerror(code);
        return result;
    }

    long negotiated = CURL_HTTP_VERSION_NONE;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &negotiated);
    result.negotiated_http = curl_http_name(negotiated);
    if (!state.headers_sent) {
        state.status = result.status;
        state.negotiated_http = result.negotiated_http;
        send_stream_headers(state);
        result.response_started = state.headers_sent;
    }
    if (state.chunked && !state.send_failed && !send_all(client, "0\r\n\r\n", 5)) {
        state.send_failed = true;
    }
    if (state.send_failed) result.error = "client connection closed while streaming response";
    return result;
}

TransferResult perform_request(CurlWorker& worker, const Request& request, const Config& config,
                               const std::string& url, SOCKET client) {
    const bool plain_http = url.rfind("http://", 0) == 0;
    long requested_version = CURL_HTTP_VERSION_1_1;
    if (!plain_http) {
        requested_version = CURL_HTTP_VERSION_3;
        if (config.http_version == "2") requested_version = CURL_HTTP_VERSION_2TLS;
        else if (config.http_version == "3") requested_version = CURL_HTTP_VERSION_3ONLY;
    }

    const bool auto_http3 = !plain_http && config.http_version == "auto";
    const long connect_timeout = auto_http3 ? kAutoHttp3ConnectTimeoutMs : kConnectTimeoutMs;
    TransferResult result = perform_request_once(
        worker, request, config, url, client, requested_version, connect_timeout);
    const std::string method = lower(request.method);
    const bool safe_to_retry = method == "get" || method == "head" || method == "options";
    const bool h3_error = result.curl_code == CURLE_HTTP3 ||
                          result.curl_code == CURLE_QUIC_CONNECT_ERROR;
    const bool auto_connect_error = auto_http3 &&
        (result.curl_code == CURLE_OPERATION_TIMEDOUT || result.curl_code == CURLE_COULDNT_CONNECT);
    if ((!h3_error && !auto_connect_error) || result.response_started ||
        plain_http || !safe_to_retry) {
        return result;
    }

    curl_easy_cleanup(worker.easy);
    worker.easy = nullptr;
    const long retry_version = config.http_version == "auto"
        ? CURL_HTTP_VERSION_2TLS
        : requested_version;
    return perform_request_once(
        worker, request, config, url, client, retry_version, kConnectTimeoutMs);
}

void log_request(const Request& request, const TransferResult& result, const std::string& url) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << request.method << ' ' << url << " -> " << result.status;
    if (!result.negotiated_http.empty()) std::cout << " [" << result.negotiated_http << ']';
    if (!result.error.empty()) std::cout << " | " << result.error;
    std::cout << std::endl;
}

bool build_upstream_url(Request& request, std::string& url, std::string& error) {

	
    const bool https = request.method.rfind(kHttpsMethodMarker, 0) == 0;

    if (https)
        request.method.erase(0, std::strlen(kHttpsMethodMarker));

    if (request.method.empty()) {
        error = "Missing HTTP method";
        return false;
    }

    if (request.target.rfind("http://", 0) == 0 ||
        request.target.rfind("https://", 0) == 0) {
        url = request.target;
        request.plain_http = request.target.rfind("http://", 0) == 0;
        return true;
    }

    const std::string* host = find_header(request.headers, "host");
    if (!host || host->empty() || request.target.empty() || request.target[0] != '/') {
        error = "Host header and origin-form request target are required";
        return false;
    }

    request.plain_http = !https;
    url = (https ? "https://" : "http://") + *host + request.target;
    return true;
}

using Clock = std::chrono::steady_clock;

struct ClientConnection {
    SOCKET socket = INVALID_SOCKET;
    std::string pending;
    bool reused = false;
    Clock::time_point idle_since = Clock::now();
};

struct WorkQueue {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::shared_ptr<ClientConnection>> items;
    std::deque<std::shared_ptr<ClientConnection>> returned;
    std::unordered_set<SOCKET> active;
    bool stopping = false;
};

bool handle_request(ClientConnection& connection, CurlWorker& worker, const Config& config) {
    const DWORD receive_timeout = connection.reused
        ? kReusedClientTimeoutMs
        : kInitialClientTimeoutMs;
    setsockopt(connection.socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&receive_timeout), sizeof(receive_timeout));
    setsockopt(connection.socket, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&kClientSendTimeoutMs), sizeof(kClientSendTimeoutMs));

    Request request;
    std::string error;
    if (!read_request(connection.socket, connection.pending, request, error)) {
        if (!error.empty()) send_text_response(connection.socket, 400, error + "\n");
        return false;
    }

    if (request.method == "GET" && request.target == "/health") {
        send_text_response(connection.socket, 200, "ok\n");
        return false;
    }

    std::string url;
    if (!build_upstream_url(request, url, error)) {
        send_text_response(connection.socket, 400, error + "\n");
        return false;
    }

    const bool keep_alive = request_wants_keep_alive(request);
    TransferResult result = perform_request(
        worker, request, config, url, connection.socket);
	if (!result.response_started) {
		send_text_response(
			connection.socket, 502, "Upstream request failed: " + result.error + "\n");
	}
	else if (result.curl_code != CURLE_OK) {
		enable_abortive_close(connection.socket);
	}
    log_request(request, result, url);
    return keep_alive && result.error.empty();
}

BOOL WINAPI on_console_signal(DWORD signal) {
    if (signal != CTRL_C_EVENT && signal != CTRL_BREAK_EVENT && signal != CTRL_CLOSE_EVENT) return FALSE;
    g_running = false;
    wake_dispatcher();
    return TRUE;
}

void print_usage() {
    std::cout
        << "Usage: fiddler-impersonate-proxy [options]\n"
        << "  --listen ADDRESS    Listen address (default 127.0.0.1)\n"
        << "  --port PORT         Listen port (default: automatic)\n"
        << "  --profile NAME      curl-impersonate profile (default chrome150)\n"
        << "  --http auto|2|3     Upstream HTTP policy (default auto)\n"
        << "  --workers COUNT     Concurrent request workers (default 32)\n"
        << "  --help              Show this help\n";
}

bool parse_args(int argc, char** argv, Config& config) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") {
            print_usage();
            return false;
        }
        if (i + 1 >= argc) {
            std::cerr << "Missing value for " << arg << std::endl;
            return false;
        }
        const std::string value = argv[++i];
        if (arg == "--listen") config.listen_address = value;
        else if (arg == "--port") {
            const int port = std::stoi(value);
            if (port < 0 || port > 65535) throw std::out_of_range("port");
            config.port = static_cast<unsigned short>(port);
        } else if (arg == "--profile") config.profile = value;
        else if (arg == "--http") config.http_version = lower(value);
        else if (arg == "--workers") {
            const int workers = std::stoi(value);
            if (workers < 1 || workers > 256) throw std::out_of_range("workers");
            config.workers = static_cast<unsigned int>(workers);
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return false;
        }
    }
    if (config.http_version != "auto" && config.http_version != "2" && config.http_version != "3") {
        std::cerr << "--http must be auto, 2, or 3" << std::endl;
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Config config;
    try {
        if (!parse_args(argc, argv, config)) return argc > 1 ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "Invalid command line: " << error.what() << std::endl;
        return 1;
    }

    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::cerr << "curl_global_init failed" << std::endl;
        WSACleanup();
        return 1;
    }

    const curl_version_info_data* curl_version = curl_version_info(CURLVERSION_NOW);
    const bool has_http2 = (curl_version->features & CURL_VERSION_HTTP2) != 0;
    const bool has_http3 = (curl_version->features & CURL_VERSION_HTTP3) != 0;
    const bool has_brotli = (curl_version->features & CURL_VERSION_BROTLI) != 0;
    const bool has_zstd = (curl_version->features & CURL_VERSION_ZSTD) != 0;
    if (!has_http2 || (config.http_version == "3" && !has_http3)) {
        std::cerr << "Loaded libcurl lacks the requested HTTP feature" << std::endl;
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }

    SetConsoleCtrlHandler(on_console_signal, TRUE);
    g_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listener == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.port);
    if (inet_pton(AF_INET, config.listen_address.c_str(), &address.sin_addr) != 1) {
        std::cerr << "Invalid IPv4 listen address: " << config.listen_address << std::endl;
        closesocket(g_listener);
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }
    if (bind(g_listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(g_listener, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "bind/listen failed: " << WSAGetLastError() << std::endl;
        closesocket(g_listener);
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }

    if (config.port == 0) {
        int address_size = sizeof(address);
        if (getsockname(g_listener, reinterpret_cast<sockaddr*>(&address), &address_size) == SOCKET_ERROR) {
            std::cerr << "getsockname failed: " << WSAGetLastError() << std::endl;
            closesocket(g_listener);
            curl_global_cleanup();
            WSACleanup();
            return 1;
        }
        config.port = ntohs(address.sin_port);
    }

    SOCKET wake_receiver = INVALID_SOCKET;
    SOCKET wake_sender = INVALID_SOCKET;
    if (!create_wake_sockets(wake_receiver, wake_sender)) {
        std::cerr << "dispatcher wake socket initialization failed" << std::endl;
        if (wake_receiver != INVALID_SOCKET) closesocket(wake_receiver);
        if (wake_sender != INVALID_SOCKET) closesocket(wake_sender);
        closesocket(g_listener);
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }
    g_wake_sender = wake_sender;

    CurlShareState curl_share;
    curl_share.handle = curl_share_init();
    if (!curl_share.handle ||
        curl_share_setopt(curl_share.handle, CURLSHOPT_USERDATA, &curl_share) != CURLSHE_OK ||
        curl_share_setopt(curl_share.handle, CURLSHOPT_LOCKFUNC, lock_curl_share) != CURLSHE_OK ||
        curl_share_setopt(curl_share.handle, CURLSHOPT_UNLOCKFUNC, unlock_curl_share) != CURLSHE_OK ||
        curl_share_setopt(curl_share.handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS) != CURLSHE_OK ||
        curl_share_setopt(curl_share.handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION) != CURLSHE_OK) {
        std::cerr << "curl share initialization failed" << std::endl;
        if (curl_share.handle) curl_share_cleanup(curl_share.handle);
        closesocket(wake_receiver);
        closesocket(wake_sender);
        g_wake_sender = INVALID_SOCKET;
        closesocket(g_listener);
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }

    std::cout << "Fiddler browser proxy listening on http://" << config.listen_address << ':' << config.port
              << " | profile=" << config.profile << " | http=" << config.http_version
              << " | workers=" << config.workers << std::endl;
    std::cout << "libcurl=" << curl_version->version << " | HTTP/2=" << (has_http2 ? "yes" : "no")
              << " | HTTP/3=" << (has_http3 ? "yes" : "no")
              << " | Brotli=" << (has_brotli ? "yes" : "no")
              << " | Zstd=" << (has_zstd ? "yes" : "no") << std::endl;
    std::cout << "Health check: http://" << config.listen_address << ':' << config.port << "/health" << std::endl;

    WorkQueue work_queue;
    std::vector<std::thread> workers;
    workers.reserve(config.workers);
    for (unsigned int i = 0; i < config.workers; ++i) {
        workers.emplace_back([&]() {
            CurlWorker curl_worker(curl_share.handle);
            while (true) {
                std::shared_ptr<ClientConnection> connection;
                {
                    std::unique_lock<std::mutex> lock(work_queue.mutex);
                    work_queue.ready.wait(lock, [&]() {
                        return work_queue.stopping || !work_queue.items.empty();
                    });
                    if (work_queue.stopping && work_queue.items.empty()) return;
                    connection = work_queue.items.front();
                    work_queue.items.pop_front();
                    work_queue.active.insert(connection->socket);
                }

                const bool keep_alive = handle_request(*connection, curl_worker, config);
                bool returned = false;
                {
                    std::lock_guard<std::mutex> lock(work_queue.mutex);
                    work_queue.active.erase(connection->socket);
                    if (keep_alive && !work_queue.stopping) {
                        connection->reused = true;
                        connection->idle_since = Clock::now();
                        work_queue.returned.push_back(connection);
                        returned = true;
                    }
                }
                if (returned) {
                    wake_dispatcher();
                } else {
                    closesocket(connection->socket);
                    connection->socket = INVALID_SOCKET;
                }
            }
        });
    }

    std::vector<std::shared_ptr<ClientConnection>> idle_connections;
    while (g_running) {
        std::deque<std::shared_ptr<ClientConnection>> returned_connections;
        {
            std::lock_guard<std::mutex> lock(work_queue.mutex);
            returned_connections.swap(work_queue.returned);
        }

        std::vector<std::shared_ptr<ClientConnection>> ready_connections;
        while (!returned_connections.empty()) {
            auto connection = returned_connections.front();
            returned_connections.pop_front();
            if (connection->pending.empty()) {
                idle_connections.push_back(connection);
            } else {
                ready_connections.push_back(connection);
            }
        }

        const auto now = Clock::now();
        std::vector<std::shared_ptr<ClientConnection>> live_connections;
        live_connections.reserve(idle_connections.size());
        for (const auto& connection : idle_connections) {
            const auto timeout = connection->reused
                ? std::chrono::milliseconds(kReusedClientTimeoutMs)
                : std::chrono::milliseconds(kInitialClientTimeoutMs);
            if (now - connection->idle_since >= timeout) {
                closesocket(connection->socket);
                connection->socket = INVALID_SOCKET;
            } else {
                live_connections.push_back(connection);
            }
        }
        idle_connections.swap(live_connections);

        std::vector<WSAPOLLFD> poll_fds;
        poll_fds.reserve(idle_connections.size() + 2);
        poll_fds.push_back({wake_receiver, POLLRDNORM, 0});
        poll_fds.push_back({g_listener, POLLRDNORM, 0});
        for (const auto& connection : idle_connections) {
            poll_fds.push_back({connection->socket, POLLRDNORM, 0});
        }

        const int poll_result = WSAPoll(
            poll_fds.data(), static_cast<ULONG>(poll_fds.size()), 1000);
        if (poll_result == SOCKET_ERROR) {
            if (g_running) std::cerr << "WSAPoll failed: " << WSAGetLastError() << std::endl;
            break;
        }

        if (poll_fds[0].revents != 0) drain_wake_socket(wake_receiver);
        if (!g_running) break;

        if ((poll_fds[1].revents & POLLRDNORM) != 0) {
            SOCKET client = accept(g_listener, nullptr, nullptr);
            if (client != INVALID_SOCKET) {
                auto connection = std::make_shared<ClientConnection>();
                connection->socket = client;
                connection->idle_since = Clock::now();
                idle_connections.push_back(connection);
            } else if (g_running) {
                std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
            }
        }

        live_connections.clear();
        live_connections.reserve(idle_connections.size());
        const std::size_t polled_count = poll_fds.size() - 2;
        for (std::size_t i = 0; i < idle_connections.size(); ++i) {
            auto connection = idle_connections[i];
            if (i >= polled_count) {
                live_connections.push_back(connection);
                continue;
            }
            const short events = poll_fds[i + 2].revents;
            if ((events & POLLRDNORM) != 0) {
                ready_connections.push_back(connection);
            } else if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                closesocket(connection->socket);
                connection->socket = INVALID_SOCKET;
            } else {
                live_connections.push_back(connection);
            }
        }
        idle_connections.swap(live_connections);

        if (!ready_connections.empty()) {
            {
                std::lock_guard<std::mutex> lock(work_queue.mutex);
                for (const auto& connection : ready_connections) {
                    work_queue.items.push_back(connection);
                }
            }
            work_queue.ready.notify_all();
        }
    }

    for (const auto& connection : idle_connections) {
        closesocket(connection->socket);
        connection->socket = INVALID_SOCKET;
    }
    {
        std::lock_guard<std::mutex> lock(work_queue.mutex);
        work_queue.stopping = true;
        for (const auto& connection : work_queue.items) {
            closesocket(connection->socket);
            connection->socket = INVALID_SOCKET;
        }
        work_queue.items.clear();
        for (const auto& connection : work_queue.returned) {
            closesocket(connection->socket);
            connection->socket = INVALID_SOCKET;
        }
        work_queue.returned.clear();
        for (SOCKET client : work_queue.active) shutdown(client, SD_BOTH);
    }
    work_queue.ready.notify_all();
    for (auto& worker : workers) worker.join();

    closesocket(g_listener);
    g_listener = INVALID_SOCKET;
    g_wake_sender = INVALID_SOCKET;
    closesocket(wake_receiver);
    closesocket(wake_sender);
    curl_share_cleanup(curl_share.handle);
    curl_global_cleanup();
    WSACleanup();
    return 0;
}
