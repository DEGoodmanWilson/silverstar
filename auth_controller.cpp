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

#include <fstream>
#include <sstream>
#include <chrono>
#include <regex>
#include <random>

#include <jwt/jwt.hpp>
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>
#include <inja/inja.hpp>
#include <sodium.h>

#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>

#if defined(__has_include)

#if __has_include(<experimental/optional>)

#define OPT_NS std::experimental
#include <experimental/optional>

#elif __has_include(<optional>)

#define OPT_NS std
#include <optional>

#endif

#else // no __has_include

#error Silverstar requires std::experimental::optional or std::optional to work!

#endif


static const std::string SILVERSTAR{"silverstar"};

template<typename ... Args>
std::string string_format_(const std::string &format, Args ... args)
{
    size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format.c_str(), args ...);
    return std::string{buf.get(), buf.get() + size - 1}; // We don't want the '\0' inside
}

OPT_NS::optional<jwt::jwt_object> validate_jwt_(const luna::headers &headers, const std::string &public_key)
{
// We have to verify that the requester has a valid token
// get the token TODO add this functionality into Luna!!
    if (!headers.count("Authorization"))
    {
        return OPT_NS::nullopt;
    }

// Ensure that the header is of the form "Bearer abc", and extract the encoded bit
    std::regex bearer_regex(R"(Bearer (.+))"); // We should look into also accepting RFC 4648
    std::smatch bearer_match;
    if (!std::regex_match(headers.at("Authorization"), bearer_match, bearer_regex) ||
        (bearer_match.size() != 2))
    {
        return OPT_NS::nullopt;
    }

// The first sub_match is the whole string; the next
// sub_match is the first parenthesized expression.
    auto token = bearer_match[1].str();

// This is a JWT—decode it then verify it!
    jwt::jwt_object dec_obj;
    try
    {
        dec_obj = jwt::decode(token, jwt::params::algorithms({"rs256"}), jwt::params::secret(public_key));
    }
    catch (const std::runtime_error &e)
    {
        luna::error_log(luna::log_level::DEBUG, e.what());
        return OPT_NS::nullopt;
    }

    if (!dec_obj.has_claim("sub"))
    {
        return OPT_NS::nullopt;
    }

    return dec_obj;
}

auth_controller::auth_controller(std::shared_ptr<luna::router> router, configuration config) :
        config_{config}
{
    // Endpoints for:
    //  1. Account creation
    //  2. Logging in
    //  4. Email verification and (planned?) re-verification
    //  5. Changing password
    // Planned:
    //  6. Changing email
    //  Eventually want to add support for roles and access levels and so forth

    router->handle_request(luna::request_method::POST,
                           "/register",
                           std::bind(&auth_controller::register_, this, std::placeholders::_1),
                           {
                                   {
                                           "email",    luna::parameter::required, luna::parameter::validate(luna::parameter::regex,
                                                                                                            std::regex{
                                                                                                                    R"(.+\@.+\..+)"})
                                   },
                                   // require passwords to be at least 8 characters. Really this should be checked in FE, but a second check here is good too for folks who want to bypass the FE entirely.
                                   {
                                           "password", luna::parameter::required, luna::parameter::validate([](const std::string &a,
                                                                                                               int length) -> bool
                                                                                                            {
                                                                                                                return a.length() >=
                                                                                                                       length;
                                                                                                            },
                                                                                                            8)
                                   }
                           });

    router->handle_request(luna::request_method::GET,
                           "/confirm",
                           std::bind(&auth_controller::confirm_, this, std::placeholders::_1),
                           {
                                   {"email", true},
                                   {"token", true}
                           });

    router->handle_request(luna::request_method::GET,
                           "/login",
                           std::bind(&auth_controller::login_, this, std::placeholders::_1));

    router->handle_request(luna::request_method::POST,
                           "/password",
                           std::bind(&auth_controller::change_password_, this, std::placeholders::_1),
                           {
                                   // require passwords to be at least 8 characters. Really this should be checked in FE, but a second check here is good too for folks who want to bypass the FE entirely.
                                   {
                                           "password", luna::parameter::required, luna::parameter::validate([](const std::string &a,
                                                                                                               int length) -> bool
                                                                                                            {
                                                                                                                return a.length() >=
                                                                                                                       length;
                                                                                                            },
                                                                                                            8)
                                   }
                           });

}

luna::response auth_controller::register_(const luna::request &request)
{
    const auto email = request.params.at("email");
    auto password = request.params.at("password");
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
    password = hashed_password;

    // Connect to DB
    auto client = config_.db_pool->acquire();
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
                bsoncxx::builder::stream::document{} << "email" << email << "password" << password
                                                     << bsoncxx::builder::stream::finalize);
    }

    // Create a token
    // Seed with a real random value, if available
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<uint64_t> dis64(0, UINT64_MAX);
    std::string token = string_format_("%08x%08x%08x%08x", dis64(gen), dis64(gen), dis64(gen), dis64(gen));


    // store in the DB, make it viable for the specified amount of time.
    auto expiry = std::chrono::system_clock::now() + config_.email_verification_window_seconds;
    auto expiry_seconds = std::chrono::time_point_cast<std::chrono::seconds>(expiry);

    auto expiry_value = expiry_seconds.time_since_epoch();
    long expiry_duration = expiry_value.count();

    provisional_users.update_one(
            bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{} << "$set" << bsoncxx::builder::stream::open_document <<
                                                 "token" << token << "expiry" << expiry_value.count()
                                                 << bsoncxx::builder::stream::close_document
                                                 << bsoncxx::builder::stream::finalize);
    // Send confirmation email via mailgun
    std::string link{config_.domain + "/api/v1/confirm?token=" + token + "&email=" + email};

    nlohmann::json mail_data;
    mail_data["link"] = link;
    mail_data["email"] = email;
    mail_data["service_name"] = config_.service_name;
    mail_data["admin_name"] = config_.admin_name;

    inja::Environment env{"./templates/"};
    auto mail_body_html = env.render_template(env.parse_template("confirm_email.html"), mail_data);
    auto mail_body_text = env.render_template(env.parse_template("confirm_email.txt"), mail_data);
    auto mail_subject = env.render_template(env.parse_template("confirm_email_subject.txt"), mail_data);

    auto mailgun_result = cpr::Post(cpr::Url{"https://api.mailgun.net/v3/"+config_.mailgun_domain+"/messages"},
                                    cpr::Payload{{"to",      email},
                                                 {"from",    config_.mailgun_email_source},
                                                 {"subject", mail_subject},
                                                 {"html",    mail_body_html},
                                                 {"text",    mail_body_text}},
                                    cpr::Authentication{"api", config_.mailgun_api_key});

    if (mailgun_result.status_code != 200)
    {
        throw std::runtime_error{"Mailgun request failed for " + email};
    }

    return {"OK"};
}

luna::response auth_controller::confirm_(const luna::request &request)
{
    // This is where we take in a code generated in the /create step. If not, return "OK" so we don't create a security issue that allows enumeration of accounts

    const auto email = request.params.at("email");
    const auto token = request.params.at("token");

    // Check the code. These can't be enumerated so maybe it is OK to return an error here?
    auto client = config_.db_pool->acquire();

    auto provisional_users = (*client)["magique"]["provisional_users"];

    auto provisional_user = provisional_users.find_one(
            bsoncxx::builder::stream::document{} << "email" << email << "token" << token
                                                 << bsoncxx::builder::stream::finalize);
    if (!provisional_user) // if this user doesn't exists, just return. It's ok to error here, because there isn't a way to enumerate that will reveal anything useful in a short amount of time
    {
        return 404;
    }

    // move account from provisional to confirmed. Would be cool if we could do this atomically
    provisional_users.delete_one(bsoncxx::builder::stream::document{} << "email" << email << "token" << token
                                                                      << bsoncxx::builder::stream::finalize);

    auto users = (*client)["magique"]["users"];

    // Check if it exists. Just in case we somehow got here twice.
    auto user = users.find_one(
            bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize);
    if (user)
    {
        return {"OK"};
    }

    const std::string password{(*provisional_user).view()["password"].get_utf8().value.to_string()};
    users.insert_one(bsoncxx::builder::stream::document{} << "email" << email << "password"
                                                          << password
                                                          << bsoncxx::builder::stream::finalize);


    return {"OK"};
}

luna::response auth_controller::login_(const luna::request &request)
{
    // Use basic auth
    auto authorized = luna::get_basic_authorization(request.headers);

    // if no authorization provided
    if (!authorized) return luna::unauthorized_response{"/"};

    // auth was provided, we need to check it.

    // compare the email and the hash
    // Connect to DB
    auto client = config_.db_pool->acquire();
    auto users = (*client)["magique"]["users"];
    auto user = users.find_one(
            bsoncxx::builder::stream::document{} << "email" << authorized.username
                                                 << bsoncxx::builder::stream::finalize);

    if (!user) // if not such user, throw an unauthorized
    {
        // TODO to prevent timing attacks to discover existing user accounts, we should insert a semi-random delay here to make the function closer to constant-time
        // We'll do this by just hasing the password they gave us.
        // TODO will this get optimized away?
        // hash the password. This is a C interface, booooo
        char hashed_password[crypto_pwhash_STRBYTES];

        if (crypto_pwhash_str(hashed_password,
                              authorized.password.c_str(),
                              authorized.password.length(),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        {
            /* out of memory */
            throw std::runtime_error{"Not enough memory to hash password"};
        }
        return 401;
    }

    const std::string hashed_password{(*user).view()["password"].get_utf8().value.to_string()};

    if (crypto_pwhash_str_verify
                (hashed_password.c_str(), authorized.password.c_str(), authorized.password.length()) != 0)
    {
        return 401;
    }



    //Create JWT object
    jwt::jwt_object obj{jwt::params::algorithm(jwt::algorithm::RS256), jwt::params::secret(config_.private_key)};
    obj.add_claim("iss", SILVERSTAR)
            .add_claim("sub", authorized.username)
            .add_claim("aud", "verified") // for verified users only
            .add_claim("exp", std::chrono::system_clock::now() + config_.jwt_valid_for_seconds);

    //Get the encoded SILVERSTAR/assertion
    auto enc_str = obj.signature();
    return enc_str;
}

luna::response auth_controller::change_password_(const luna::request &request)
{
    auto jwt = validate_jwt_(request.headers, config_.public_key);
    if (!jwt)
    {
        return 401;
    }

    // made it this far, we have a valid token!
    // A valid token gives us permission to change passwords.
    // To get a new token, the user must log in again.
    // All existing tokens will continue to be valid for their TTL.
    //   This is a really strange auth model.
    //   TTL needs to be quite small, then, yeah?
    //   So that password changes can go into effect within an hour?
    // TODO generate an email to the account owner that the password has been changed.

    auto email = jwt->payload().get_claim_value<std::string>("sub");


    auto password = request.params.at("password");

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
    password = hashed_password;

    // Connect to DB
    auto client = config_.db_pool->acquire();
    auto users = (*client)["magique"]["users"];

    // make sure account exists:
    auto user = users.find_one(
            bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize);
    if (!user) // if this user already exists, just return.
    {
        return 401;
    }

    users.update_one(
            bsoncxx::builder::stream::document{} << "email" << email << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{} << "$set" << bsoncxx::builder::stream::open_document <<
                                                 "password" << password
                                                 << bsoncxx::builder::stream::close_document
                                                 << bsoncxx::builder::stream::finalize);

    // Well, that seemed to work. Email the user to notify them
    nlohmann::json mail_data;
    mail_data["email"] = email;
    mail_data["service_name"] = config_.service_name;
    mail_data["admin_name"] = config_.admin_name;

    inja::Environment env{"./templates/"};
    auto mail_body_html = env.render_template(env.parse_template("password_change.html"), mail_data);
    auto mail_body_text = env.render_template(env.parse_template("password_change.txt"), mail_data);
    auto mail_subject = env.render_template(env.parse_template("password_change_subject.txt"), mail_data);

    auto mailgun_result = cpr::Post(cpr::Url{"https://api.mailgun.net/v3/" + config_.mailgun_domain + "/messages"},
                                    cpr::Payload{{"to",      email},
                                                 {"from",    config_.mailgun_email_source},
                                                 {"subject", mail_subject},
                                                 {"html",    mail_body_html},
                                                 {"text",    mail_body_text}},
                                    cpr::Authentication{"api", config_.mailgun_api_key});

    if (mailgun_result.status_code != 200)
    {
        throw std::runtime_error{"Mailgun request failed for " + email};
    }


    return {"OK"};
}