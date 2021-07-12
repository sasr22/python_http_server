# Simple http python server

## Usage:

    {
        "IP_TO_LISTEN:PORT": {
            "site_name": "SITE_DOMAIN",
            "site_alias": ["ALIAS_DOMAIN1", "ALIAS_DOMAIN1"],
            "document_root": "PATH_TO_DOCUMENT_ROOT",
            "static_root": {"static_folder1": "PATH_TO_STATIC_ROOT1", "static_folder2": "PATH_TO_STATIC_ROOT2"}
        }
    }

Value | explanation
----|----
IP_TO_LISTEN |either 0.0.0.0 (Listen to all requests (can also be *)) or 127.0.0.1/localhost (listen only to local requests), can also be a external IP address.
PORT | Port for the site to listen to.
site_name | Primary domain to answer to.
site_alias | Array of alias domains to listen to.
document_root | Primary site folder.
static_root | JSON of {"NAME": "PATH_TO_FOLDER"} (Can support multiple folders)

