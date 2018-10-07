//       _ _
//      (_) |
//   ___ _| |_   _____ _ __
//  / __| | \ \ / / _ \ '__|
//  \__ \ | |\ V /  __/ | |
//  |___/_|_| \_/ \___|_| |_ __ _ _ __
//                  / __| __/ _` | '__|
//                  \__ \ || (_| | |
//                  |___/\__\__,_|_|
//
//
// silverstar
// A web microservice for authenticating users
//
// Copyright © 2018 D.E. Goodman-Wilson
//

#pragma once

#include <string>
#include <chrono>
#include <mongocxx/pool.hpp>
#include <nlohmann/json.hpp>

class configuration
{
public:
    configuration();

    std::string app_name;
    std::string service_name;
    std::string admin_name;

    uint16_t port;
    std::string domain;

    std::string private_key;
    std::string public_key;

    std::string mongo_uri;
    std::shared_ptr<mongocxx::pool> db_pool;

    std::string mailgun_api_key;
    std::string mailgun_domain;
    std::string mailgun_email_source;

    std::chrono::seconds jwt_valid_for_seconds;
    std::chrono::seconds email_verification_window_seconds;
};

void from_json(const nlohmann::json &j, configuration &c);


