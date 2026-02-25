#pragma once

#include <curl/curl.h>

#include <string>
#include <vector>

namespace aegis {

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // Check if a package exists in its registry (HEAD request)
    bool check_package_exists(const std::string& name, const std::string& ecosystem);

    // Query OSV.dev for known vulnerabilities
    // Returns list of vulnerability descriptions (empty = clean)
    std::vector<std::string> check_osv(const std::string& name,
                                        const std::string& ecosystem);

    // Set timeout (seconds)
    void set_timeout(long seconds) { timeout_ = seconds; }

private:
    CURL* curl_ = nullptr;
    long timeout_ = 10;

    struct Response {
        long status_code = 0;
        std::string body;
    };

    Response head(const std::string& url);
    Response post(const std::string& url, const std::string& body);

    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

    std::string registry_url(const std::string& name, const std::string& ecosystem);
    std::string osv_ecosystem(const std::string& ecosystem);
};

}  // namespace aegis
