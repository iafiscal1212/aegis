#include "daemon/typosquat.h"
#include <gtest/gtest.h>

using aegis::TyposquatDetector;

TEST(TyposquatTest, ExactMatchIsSafe) {
    TyposquatDetector det(2);
    auto results = det.check("requests", "python");
    EXPECT_TRUE(results.empty());
}

TEST(TyposquatTest, DetectsSimpleTypo) {
    TyposquatDetector det(2);
    auto results = det.check("reqeusts", "python");
    ASSERT_FALSE(results.empty());
    EXPECT_EQ(results[0].popular_name, "requests");
    EXPECT_FALSE(results[0].is_combosquat);
}

TEST(TyposquatTest, DetectsCombosquat) {
    TyposquatDetector det(2);
    auto results = det.check("python-requests", "python");
    ASSERT_FALSE(results.empty());
    EXPECT_EQ(results[0].popular_name, "requests");
    EXPECT_TRUE(results[0].is_combosquat);
}

TEST(TyposquatTest, UnrelatedPackageIsSafe) {
    TyposquatDetector det(2);
    auto results = det.check("my-custom-unique-pkg-xyz", "python");
    EXPECT_TRUE(results.empty());
}

TEST(TyposquatTest, StricterThreshold) {
    TyposquatDetector det(1);
    // Distance 2 from "requests" — should not match with threshold 1
    auto results = det.check("requsets", "python");
    // Depends on exact distance; "requsets" is distance 2 from "requests"
    // With threshold 1, it should be filtered out
    for (const auto& r : results) {
        EXPECT_LE(r.levenshtein_distance, 1);
    }
}

TEST(TyposquatTest, NodePackages) {
    TyposquatDetector det(2);
    auto results = det.check("expresss", "node");
    ASSERT_FALSE(results.empty());
    EXPECT_EQ(results[0].popular_name, "express");
}

TEST(TyposquatTest, NormalizesNames) {
    TyposquatDetector det(2);
    // python-dateutil with different separators should be exact match
    auto results = det.check("python_dateutil", "python");
    EXPECT_TRUE(results.empty());
}
