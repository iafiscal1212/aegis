#include "daemon/http_client.h"

#include <cstring>
#include <stdexcept>

namespace aegis {

HttpClient::HttpClient() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("curl_easy_init failed");
    }
}

HttpClient::~HttpClient() {
    if (curl_) curl_easy_cleanup(curl_);
    curl_global_cleanup();
}

size_t HttpClient::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* resp = static_cast<std::string*>(userdata);
    resp->append(ptr, size * nmemb);
    return size * nmemb;
}

HttpClient::Response HttpClient::head(const std::string& url) {
    Response resp;
    curl_easy_reset(curl_);
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeout_);
    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);

    CURLcode rc = curl_easy_perform(curl_);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &resp.status_code);
    }
    return resp;
}

HttpClient::Response HttpClient::post(const std::string& url, const std::string& body) {
    Response resp;
    curl_easy_reset(curl_);
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, body.size());
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeout_);
    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &resp.body);

    CURLcode rc = curl_easy_perform(curl_);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &resp.status_code);
    }

    curl_slist_free_all(headers);
    return resp;
}

std::string HttpClient::registry_url(const std::string& name,
                                      const std::string& ecosystem) {
    if (ecosystem == "python") {
        return "https://pypi.org/pypi/" + name + "/json";
    } else if (ecosystem == "node") {
        return "https://registry.npmjs.org/" + name;
    } else if (ecosystem == "rust") {
        return "https://crates.io/api/v1/crates/" + name;
    }
    return "";
}

std::string HttpClient::osv_ecosystem(const std::string& ecosystem) {
    if (ecosystem == "python") return "PyPI";
    if (ecosystem == "node") return "npm";
    if (ecosystem == "rust") return "crates.io";
    return "";
}

bool HttpClient::check_package_exists(const std::string& name,
                                       const std::string& ecosystem) {
    std::string url = registry_url(name, ecosystem);
    if (url.empty()) return true;  // unknown ecosystem, assume exists

    auto resp = head(url);
    return resp.status_code == 200;
}

std::vector<std::string> HttpClient::check_osv(const std::string& name,
                                                 const std::string& ecosystem) {
    std::vector<std::string> results;

    std::string osv_eco = osv_ecosystem(ecosystem);
    if (osv_eco.empty()) return results;

    std::string body = R"({"package":{"name":")" + name +
                       R"(","ecosystem":")" + osv_eco + R"("}})";

    auto resp = post("https://api.osv.dev/v1/query", body);
    if (resp.status_code != 200) return results;

    // Minimal JSON parsing for OSV response
    // Look for "vulns" array with "id" and "summary" fields
    size_t pos = 0;
    while (true) {
        pos = resp.body.find("\"id\"", pos);
        if (pos == std::string::npos) break;

        auto id_start = resp.body.find('"', pos + 4);
        if (id_start == std::string::npos) break;
        id_start++;
        auto id_end = resp.body.find('"', id_start);
        if (id_end == std::string::npos) break;
        std::string id = resp.body.substr(id_start, id_end - id_start);

        // Find summary near this id
        std::string summary;
        auto sum_pos = resp.body.find("\"summary\"", id_end);
        if (sum_pos != std::string::npos && sum_pos < id_end + 500) {
            auto s_start = resp.body.find('"', sum_pos + 9);
            if (s_start != std::string::npos) {
                s_start++;
                auto s_end = resp.body.find('"', s_start);
                if (s_end != std::string::npos) {
                    summary = resp.body.substr(s_start, s_end - s_start);
                }
            }
        }

        results.push_back("CVE " + id + (summary.empty() ? "" : ": " + summary));
        pos = id_end;

        if (results.size() >= 5) break;  // limit results
    }

    return results;
}

}  // namespace aegis
