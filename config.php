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

    // HTTP service used to resolve countries. "%s" is replaced by the IP address
    // The endpoint should return the country code as plain text
    'geo_endpoint' => 'https://ipapi.co/%s/country/',

    // Customize displayed HTML strings if needed
    'strings' => array(
        'banned_title' => 'Accès refusé',
        'banned_message' => "Votre IP a été bannie. Contactez l'administrateur.",
        'captcha_title' => 'Vérification de sécurité',
        'captcha_label' => 'Veuillez entrer le code',
        'captcha_button' => 'Valider',
        'captcha_error' => 'Code incorrect, veuillez réessayer.',
    ),
);
