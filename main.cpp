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

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <regex>

#include <luna/luna.h>
#include <jwt/jwt.hpp>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <cpr/cpr.h>
#include <inja/inja.hpp>

#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>

static const std::string SILVERSTAR{"silverstar"};

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

std::string read_from_file(const std::string &path)
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
        std::cerr << "FILE not FOUND!!" << std::endl;
    }

    return contents.str();
}


std::string getenvstr(const std::string &key)
{
    auto val = std::getenv(key.c_str());
    return val == NULL ? std::string{} : std::string{val};
}


int main(int, char **)
{

    // determine which port to run on, default to 8080
    auto temp_port = getenvstr("PORT");
    auto port{std::strtoul(temp_port.c_str(), NULL, 0)};
    if (port == 0)
    {
        luna::error_log(luna::log_level::INFO, "Using 8080 for port");
        port = 8080;
    }

    const std::string my_uri{getenvstr("MONGO_URI")};

    if (my_uri.empty())
    {
        luna::error_log(luna::log_level::FATAL, "Invalid url specified in env MONGO_URI.");
        exit(1);
    }

    mongocxx::instance instance{};

    mongocxx::pool db_pool_{mongocxx::uri{my_uri}};

    const std::string mailgun_api_key{getenvstr("MAILGUN_API_KEY")};
    if (mailgun_api_key.empty())
    {
        luna::error_log(luna::log_level::FATAL, "Invalid apikey specified in env MAILGUN_API_KEY.");
        exit(1);
    }

    std::string domain{getenvstr("DOMAIN")};
    if (domain.empty())
    {
        luna::error_log(luna::log_level::INFO, "Using localhost for domain");
        domain = "http://localhost:8080";
    }

    luna::server server;

    // add endpoint handlers
    auto api = server.create_router("/api/v1");

    api->set_mime_type("application/json");

    // Get RSA public and private keys

    // TODO for security reasons, verify that this is actually a public key!!
    auto pub_key = read_from_file("jwtRS256.key.pub");
    if (!std::regex_search(pub_key, std::regex{R"(^-----BEGIN PUBLIC KEY-----)"}))
    {
        std::cerr << "INVALID PUBLIC KEY!" << std::endl;
        exit(1);
    }
    auto priv_key = read_from_file("jwtRS256.key");

    // TODO break this out into a separate controller object
    // Endpoints for:
    //  1. Account creation
    //  2. Logging in
    //  3. Logging out
    // Planned:
    //  4. Email verification and re-verification
    //  5. Changing password
    //  6. Changing email
    //  Eventually want to add support for roles and access levels and so forth

    api->handle_request(luna::request_method::GET, "/pubkey", [=](const auto &request) -> luna::response
    {
        return {
                "application/x-pem-file",
                pub_key
        };
    });

    api->handle_request(luna::request_method::POST, "/create", [=, &db_pool_](const auto &request) -> luna::response
                        {
                            const auto email = request.params.at("email");
                            const auto password = request.params.at("password");
                            // see if this account already exists. If it does, we need to signal this without giving too much away.
                            // Best way to do this is to return a success status code regardless.


                            // hash the password. This is a C interface, booooo
                            char hashed_password[crypto_pwhash_STRBYTES];

                            if (crypto_pwhash_str(hashed_password,
                                                  password.c_str(),
                                                  password.length(),
                                                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                  crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
                            {
                                /* out of memory */
                                throw std::runtime_error{"Not enough memory to hash password"};
                            }

                            // Connect to DB
                            auto client = db_pool_.acquire();
                            auto users = (*client)["magique"]["users"];

                            // Check if it exists
                            auto user = users.find_one(
                                    bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize);
                            if (user) // if this user already exists, just return.
                            {
                                // TODO to prevent timing attacks to discover existing user accounts, we should insert a semi-random delay here to make the function closer to constant-time
                                return {"OK"};
                            }

                            // create the provisional account if there isn't already a provisional account
                            auto provisional_users = (*client)["magique"]["provisional_users"];
                            auto provisional_user = provisional_users.find_one(
                                    bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize);
                            if (!provisional_user) // if this user doesn't already exist, provisionally, create a provisional account.
                            {
                                provisional_users.insert_one(
                                        bsoncxx::builder::stream::document{} << "email" << email << "password" << hashed_password
                                                                             << bsoncxx::builder::stream::finalize);
                            }
                            // Create a token that expires in 24 hours
                            jwt::jwt_object obj{jwt::params::algorithm(jwt::algorithm::RS256), jwt::params::secret(priv_key)};
                            obj.add_claim("iss", SILVERSTAR)
                                    .add_claim("sub", email)
                                    .add_claim("exp", std::chrono::system_clock::now() + std::chrono::hours{24})
                                    .add_claim("aud", "provisional") // for provisional use only
                                    ;
                            auto token = obj.signature();

                            // store in the DB
                            provisional_users.update_one(
                                    bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize,
                                    bsoncxx::builder::stream::document{} << "$set" << bsoncxx::builder::stream::open_document <<
                                                                         "token" << token << bsoncxx::builder::stream::close_document
                                                                         << bsoncxx::builder::stream::finalize);
                            // Send confirmation email via mailgun
                            std::string link{domain + "/api/v1/confirm?token=" + token + "&email=" + email};
                            std::string mail_body_html_template{R"(<a href="{{link}}">confirm your email</a>)"};
                            std::string mail_body_text_template = R"(Please visit this link to confirm your email: {{link}})";

                            nlohmann::json mail_data;
                            mail_data["link"] = link;
                            inja::Environment env{};
                            auto mail_body_html = env.render(mail_body_html_template, mail_data);
                            auto mail_body_text = env.render(mail_body_text_template, mail_data);

                            auto r = cpr::Post(cpr::Url{"https://api.mailgun.net/v3/mail.goodman-wilson.com/messages"},
                                               cpr::Payload{{"to",      email},
                                                            {"from",    "auth@mail.goodman-wilson.com"},
                                                            {"subject", "Verify your goodman-wilson.com account"},
                                                            {"html",    mail_body_html},
                                                            {"text",    mail_body_text}},
                                               cpr::Authentication{"api", mailgun_api_key});

                            if(r.status_code != 200)
                            {
                                throw std::runtime_error{"Mailgun request failed for " + email};
                            }

                            return {"OK"};
                        },
                        {
                                {"email",    luna::parameter::required, luna::parameter::validate(luna::parameter::regex,
                                                                                                  std::regex{
                                                                                                          R"(.+\@.+\..+)"})
                                },
                                // require passwords to be at least 8 characters.
                                {"password", luna::parameter::required, luna::parameter::validate([](const std::string &a,
                                                                                                     int length) -> bool
                                                                                                  {
                                                                                                      return a.length() >=
                                                                                                             length;
                                                                                                  },
                                                                                                  8)
                                }
                        });

    api->handle_request(luna::request_method::POST, "/confirm", [](const auto &request) -> luna::response
                        {
                            // This is where we take in a code generated in the /create step. If not, return "OK" so we don't create a security issue that allows enumeration of accounts

                            // Check the code. These can't be enumerated so maybe it is OK to return an error here?

                            // move account from provisional to confirmed

                            return {"OK"};
                        },
                        {
                                {"email", true},
                                {"code",  true}
                        });

    api->handle_request(luna::request_method::GET, "/login", [=](const auto &request) -> luna::response
    {
        // Use basic auth
        auto authorized = luna::get_basic_authorization(request.headers);

        // if no authorization provided
        if (!authorized) return luna::unauthorized_response{"/"};

        // auth was provided, we need to check it.
        luna::error_log(luna::log_level::DEBUG, authorized.username);
        // TODO just assume it's cool, let's issue a fake JWT.

        //Create JWT object
        jwt::jwt_object obj{jwt::params::algorithm(jwt::algorithm::RS256), jwt::params::secret(priv_key)};
        obj.add_claim("iss", SILVERSTAR)
                .add_claim("sub", authorized.username)
                .add_claim("aud", "verified") // for verified users only
                .add_claim("exp", std::chrono::system_clock::now() + std::chrono::hours{24});

        //Get the encoded SILVERSTAR/assertion
        auto enc_str = obj.signature();
        return enc_str;
    });

    api->handle_request(luna::request_method::GET, "/logout", [](const auto &request) -> luna::response
    {
        return 404;
    });

    // fire up the webserver
    luna::set_error_logger(error_logger);
    luna::set_access_logger(access_logger);
    server.start(port);


    return 0;
}