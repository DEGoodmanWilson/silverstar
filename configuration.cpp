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

#include "configuration.h"

#include <unordered_set>
#include <regex>
#include <fstream>

#include <base64/base64.h>


std::string read_from_file_(const std::string &path)
{
    std::stringstream contents;
    std::ifstream is{path};
    if (is)
    {
        contents << is.rdbuf();
        is.close();
    }

    else
    {
        throw std::runtime_error{"Could not read from file " + path};
    }

    return contents.str();
}

void from_json(const nlohmann::json &j, configuration &c)
{
    std::unordered_set<std::string> required{"app_name", "service_name", "admin_name", "port", "domain", "token_valid_for_seconds", "email_verification_window_seconds", "mailgun_domain", "mailgun_email_source"};

    if (!j.is_object())
    {
        throw std::runtime_error{"Configuration file is not a JSON object"};
    }

    std::string public_key_filename, private_key_filename;

    // we use a for loop to detect a) keys we don't recognize and b) to ensure all the required keys are hit
    for (auto kv = j.begin(); kv != j.end(); ++kv)
    {
        std::string key = kv.key();
        if (key == "app_name")
        {
            required.erase(key);
            c.app_name = kv.value().get<std::string>();
        }
        else if (key == "service_name")
        {
            required.erase(key);
            c.service_name = kv.value().get<std::string>();
        }
        else if (key == "admin_name")
        {
            required.erase(key);
            c.admin_name = kv.value().get<std::string>();
        }
        else if (key == "port")
        {
            required.erase(key);
            c.port = kv.value().get<uint16_t>();
        }
        else if (key == "domain")
        {
            required.erase(key);
            c.domain = kv.value().get<std::string>();
        }
        else if (key == "token_valid_for_seconds")
        {
            required.erase(key);
            c.jwt_valid_for_seconds = std::chrono::seconds{kv.value().get<uint16_t>()};
        }
        else if (key == "email_verification_window_seconds")
        {
            required.erase(key);
            c.email_verification_window_seconds = std::chrono::seconds{kv.value().get<uint16_t>()};
        }
        else if (key == "mailgun_domain")
        {
            required.erase(key);
            c.mailgun_domain = kv.value().get<std::string>();
        }
        else if (key == "mailgun_email_source")
        {
            required.erase(key);
            c.mailgun_email_source = kv.value().get<std::string>();
        }
    }

    for (const auto key : required)
    {
        // Yes I know i am throwing an exception inside a loop. Sue me. It's an easy way to discover if anything remains, and what it is.
        throw std::runtime_error{"Missing configuration key " + key};
    }
}

std::string getenvstr_(const std::string &key)
{
    auto val = std::getenv(key.c_str());
    return val == NULL ? std::string{} : std::string{val};
}

configuration::configuration() :
        mongo_uri{getenvstr_("MONGO_URI")},
        mailgun_api_key{getenvstr_("MAILGUN_API_KEY")},
        public_key{base64_decode(getenv("PUBLIC_KEY"))},
        private_key{base64_decode(getenv("PRIVATE_KEY"))}
{
    if (mongo_uri.empty())
    {
        std::runtime_error{"missing env var MONGO_URI."};
    }

    if (mailgun_api_key.empty())
    {
        std::runtime_error{"missing env var MAILGUN_API_KEY."};
    }

    db_pool = std::make_shared<mongocxx::pool>(mongocxx::uri{mongo_uri});


    if (public_key.empty())
    {
        std::runtime_error{"missing env var PUBLIC_KEY."};
    }

    if (mailgun_api_key.empty())
    {
        std::runtime_error{"missing env var PRIVATE_KEY."};
    }

    // for security reasons, verify that this is actually a public key!!
    if (!std::regex_search(public_key, std::regex{R"(^-----BEGIN PUBLIC KEY-----)"}))
    {
        throw std::runtime_error{"Invalid public key"};
    }
}