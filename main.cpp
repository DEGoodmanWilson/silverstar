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

#include "auth_controller.h"

#include <iostream>
#include <fstream>

#include <luna/luna.h>

#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>


void error_logger(luna::log_level level, const std::string &message)
{
    switch (level)
    {
        case luna::log_level::DEBUG:
            std::cerr << "[  DEBUG] " << message << std::endl;
            break;
        case luna::log_level::INFO:
            std::cerr << "[   INFO] " << message << std::endl;
            break;
        case luna::log_level::WARNING:
            std::cerr << "[WARNING] " << message << std::endl;
            break;
        case luna::log_level::ERROR:
            std::cerr << "[  ERROR] " << message << std::endl;
            break;
        case luna::log_level::FATAL:
            std::cerr << "[  FATAL] " << message << std::endl;
            break;
    }
}

void access_logger(const luna::request &request, const luna::response &response)
{
    std::cout << request.ip_address << ": " << luna::to_string(request.method) << " [" << response.status_code << "] "
              << request.path << " " << request.http_version << " "
              << (request.headers.count("user-agent") ? request.headers.at("user-agent") : "[no user-agent]") << " { "
              << std::chrono::duration_cast<std::chrono::microseconds>(request.end - request.start).count() << "us } "
              << std::endl;
}


int main(int, char **)
{
    mongocxx::instance instance{};

    std::ifstream i("silverstar.json");
    nlohmann::json config_json;
    i >> config_json;
    i.close();

    configuration config = config_json;

    luna::server server;

    // add endpoint handlers
    auto api = server.create_router("/api/v1");
    auth_controller auth_controller{api, config};

    // fire up the webserver
    luna::set_error_logger(error_logger);
    luna::set_access_logger(access_logger);
    server.start(config.port);


    return 0;
}


//#include <iostream>
//#include <sodium.h>
//
//int main(void)
//{
//    const std::string password{"tLWZHo%nxig(Ts(AHzHCq8X.GH$twYuZ4F6ZrsQ6amk386BAK7C#MJ>bD+.99)gU"};
////    const std::string password{"101cannon"};
////    char hashed_password[crypto_pwhash_STRBYTES];
//    const std::string hashed_password{"$argon2id$v=19$m=65536,t=2,p=1$ddeE6hGOB00Zx8pmGJW3SQ$5r15cKAlLkr5zjezA6ViVCGVyrRVujSBA7ihPLDzdpA"};
////    const std::string hashed_password{"$argon2id$v=19$m=65536,t=2,p=1$6vWEJNssbvTuPWh62iGOCg$WukbaFktedxyTwgts6hgqvDw4NqfmgUs2cHBCDmWanA"};
//
////    if (crypto_pwhash_str
////                (hashed_password, password.c_str(), password.length(),
////                 crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
////    {
////    }
//
//    if (crypto_pwhash_str_verify
//                (hashed_password.c_str(), password.c_str(), password.length()) != 0)
//    {
//        std::cout << "WRONG" << std::endl;
//    }
//    else
//        std::cout << "RIGHT" << std::endl;
//}