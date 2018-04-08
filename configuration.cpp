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

void from_json(const nlohmann::json &j, configuration &c)
{
    std::unordered_set<std::string> required{"port", "domain"};

    if (!j.is_object())
    {
        throw std::runtime_error{"Configuration file is not a JSON object"};
    }

    // we use a for loop to detect a) keys we don't recognize and b) to ensure all the required keys are hit
    for (auto kv = j.begin(); kv != j.end(); ++kv)
    {
        std::string key = kv.key();

        if (key == "port")
        {
            required.erase(key);
            c.port = kv.value().get<uint16_t>();
        }
        else if (key == "domain")
        {
            required.erase(key);
            c.domain = kv.value().get<std::string>();
        }
        else
        {
            throw std::runtime_error{"Unrecognized configuration key " + key};
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
        mailgun_api_key{getenvstr_("MAILGUN_API_KEY")}
{
    if (mongo_uri.empty())
    {
        std::runtime_error{"Invalid url specified in env MONGO_URI."};
    }

    if (mailgun_api_key.empty())
    {
        std::runtime_error{"Invalid url specified in env MAILGUN_API_KEY."};
    }

    db_pool = std::make_shared<mongocxx::pool>(mongocxx::uri{mongo_uri});
}