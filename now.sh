#!/bin/bash

now -e MONGO_URI=@silverstar_mongo_uri -e MAILGUN_API_KEY=@silverstar_mailgun_api_key -e PUBLIC_KEY=@silverstar_public_key -e PRIVATE_KEY=@silverstar_private_key
