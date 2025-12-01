<?php
return array(
    // Countries that can bypass the CAPTCHA challenge (ISO 3166-1 alpha-2 codes)
    'allowed_countries' => array('FR', 'DE'),

    // Ban duration in seconds when the visitor fails the captcha too many times
    'ban_duration' => 86400, // 24 hours

    // Maximum failed captcha attempts before banning the IP
    'failed_attempt_limit' => 3,

    // How long a generated captcha stays valid in the session (seconds)
    'captcha_ttl' => 900,

    // Cache duration for IP geolocation results (seconds)
    'geo_cache_ttl' => 86400,

    // Directory where runtime files are stored (state, cache)
    'storage_path' => __DIR__ . '/var',

    // Probability for running background purge on each request (0-1)
    'purge_probability' => 0.15,

    // Optional MaxMind MMDB (GeoLite2 Country, etc.). If present, used before any HTTP lookup
    'mmdb_path' => __DIR__ . '/var/GeoLite2-Country.mmdb',

    // Local intranet HTTP service used to resolve countries (returns JSON)
    'geo_local_endpoint' => 'https://tools.bibliossimo.info/whois/api.php?ip=%s',

    // Secondary public HTTP service (plain text country code)
    'geo_endpoint' => 'https://ipapi.co/%s/country/',

    // Local GeoIP database (CIDR;COUNTRY) used before remote lookups
    'local_geo_db' => __DIR__ . '/var/geoip_local.csv',

    // Optional URL to refresh the local database (plain text in the same format)
    'local_geo_update_url' => null,

    // Log file options
    'log_file' => __DIR__ . '/var/guard.log',
    'log_level' => 'info', // debug, info, error
    'log_max_bytes' => 524288, // 512 KB

    // Customize displayed HTML strings if needed
    'strings' => array(
        'banned_title' => 'Access denied',
        'banned_message' => 'Your IP has been banned. Contact the administrator.',
        'captcha_title' => 'Security check',
        'captcha_label' => 'Please type the code',
        'captcha_button' => 'Submit',
        'captcha_error' => 'Incorrect code, please try again.',
    ),
);
