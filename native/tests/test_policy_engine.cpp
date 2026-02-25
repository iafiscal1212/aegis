#include "daemon/database.h"
#include "daemon/http_client.h"
#include "daemon/policy_engine.h"
#include "daemon/typosquat.h"
#include <gtest/gtest.h>
#include <cstdio>

class PolicyEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_path_ = "/tmp/aegis_test_policy.db";
        db_ = std::make_unique<aegis::Database>(db_path_);
        db_->initialize();
        typo_ = std::make_unique<aegis::TyposquatDetector>(2);
        http_ = std::make_unique<aegis::HttpClient>();
        engine_ = std::make_unique<aegis::PolicyEngine>(*db_, *typo_, *http_);
    }

    void TearDown() override {
        engine_.reset();
        http_.reset();
        typo_.reset();
        db_.reset();
        std::remove(db_path_.c_str());
    }

    std::string db_path_;
    std::unique_ptr<aegis::Database> db_;
    std::unique_ptr<aegis::TyposquatDetector> typo_;
    std::unique_ptr<aegis::HttpClient> http_;
    std::unique_ptr<aegis::PolicyEngine> engine_;
};

TEST_F(PolicyEngineTest, AllowsKnownPackage) {
    auto result = engine_->check_command("pip install requests");
    EXPECT_EQ(result.action, "allow");
}

TEST_F(PolicyEngineTest, DetectsTyposquat) {
    auto result = engine_->check_command("pip install reqeusts");
    EXPECT_NE(result.action, "allow");
    EXPECT_FALSE(result.alerts.empty());
}

TEST_F(PolicyEngineTest, ParsesPipCommand) {
    auto result = engine_->check_command("pip install requests numpy pandas");
    EXPECT_EQ(result.action, "allow");
}

TEST_F(PolicyEngineTest, ParsesNpmCommand) {
    auto result = engine_->check_command("npm install express");
    EXPECT_EQ(result.action, "allow");
}

TEST_F(PolicyEngineTest, IgnoresUnknownManagers) {
    auto result = engine_->check_command("apt-get install vim");
    EXPECT_EQ(result.action, "allow");
}

TEST_F(PolicyEngineTest, AgentEscalation) {
    auto result = engine_->check_command("pip install reqeusts", "claude");
    EXPECT_EQ(result.action, "block");
}
