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

#include "configuration.h"

#include <luna/luna.h>
#include <mongocxx/pool.hpp>

class auth_controller
{
public:
    auth_controller(std::shared_ptr<luna::router> router, configuration config);

private:
    luna::response register_(const luna::request &request);

    luna::response confirm_(const luna::request &request);

    luna::response login_(const luna::request &request);

    luna::response relogin_(const luna::request &request);

    luna::response change_password_(const luna::request &request);

    configuration config_;
};