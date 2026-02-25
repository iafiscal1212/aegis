#pragma once

#include <string>
#include <vector>

namespace aegis {

struct TyposquatMatch {
    std::string popular_name;
    double score;
    int levenshtein_distance;
    bool is_combosquat;
};

class TyposquatDetector {
public:
    explicit TyposquatDetector(int threshold = 2);

    // Check a package name, returns match if suspicious
    std::vector<TyposquatMatch> check(const std::string& name,
                                       const std::string& ecosystem = "python") const;

    // Change threshold
    void set_threshold(int t) { threshold_ = t; }

private:
    int threshold_;

    static std::string normalize(const std::string& name);
    static int levenshtein(const std::string& a, const std::string& b);
    static double jaro_winkler(const std::string& a, const std::string& b);
    static double combined_score(const std::string& a, const std::string& b);
    static bool is_combosquat(const std::string& name, const std::string& popular);

    static const std::vector<std::string>& python_packages();
    static const std::vector<std::string>& node_packages();
    static const std::vector<std::string>& rust_packages();

    static const std::vector<std::string> COMBO_PREFIXES;
    static const std::vector<std::string> COMBO_SUFFIXES;
};

}  // namespace aegis
