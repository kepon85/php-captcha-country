# php-captcha-country

Protection légère qui affiche un CAPTCHA aux visiteurs en dehors d'une liste de pays autorisés avant de charger votre application. Pensée pour `auto_prepend_file` afin de filtrer chaque requête sans dépendances externes.

## Fonctionnement

1. Le script identifie l'adresse IP (supporte `HTTP_CF_CONNECTING_IP`, `X-Forwarded-For`, etc.).
2. La géolocalisation du pays est récupérée via un service HTTP configurable puis mise en cache dans `var/state.json`.
3. Si le pays est autorisé, la requête continue normalement.
4. Sinon un CAPTCHA (image PNG avec GD, ou texte si GD indisponible) est affiché. En cas d'échec répétitif, l'IP est bannie temporairement.
5. Les bannissements, tentatives et cache Geo sont purgés automatiquement en arrière-plan.

Compatible PHP 5.6 à 8.4, sans Composer.

## Installation

1. Copier le dépôt sur votre serveur.
2. Vérifier que le répertoire `var/` est inscriptible par PHP (fichier d'état et cache).
3. (Optionnel) Activer GD pour obtenir une image CAPTCHA plus lisible.
4. Ajouter dans votre `php.ini` ou configuration virtuelle :

```ini
auto_prepend_file="/chemin/vers/prepend.php"
```

5. Adapter la configuration si nécessaire (voir ci-dessous).

## Configuration (`config.php`)

Le fichier renvoie un tableau associatif :

- `allowed_countries` : codes pays autorisés sans CAPTCHA (ex. `array('FR', 'DE')`).
- `ban_duration` : durée du bannissement en secondes après trop d'échecs.
- `failed_attempt_limit` : nombre d'échecs CAPTCHA avant le bannissement.
- `captcha_ttl` : durée de validité du code généré (secondes).
- `geo_cache_ttl` : durée de cache pour la géolocalisation IP.
- `storage_path` : répertoire pour `state.json` (bans, cache, tentatives).
- `purge_probability` : probabilité (0-1) de purger les entrées expirées à chaque requête.
- `geo_endpoint` : URL du service retournant le code pays ( `%s` remplacé par l'IP ).
- `strings` : personnalisation des textes affichés.

## Personnalisation rapide

- **Pays autorisés** : modifiez `allowed_countries`.
- **Durée de bannissement** : ajustez `ban_duration`.
- **Seuil d'échec** : ajustez `failed_attempt_limit`.
- **Service GeoIP** : changez `geo_endpoint` (doit répondre avec un code pays, ex. `https://ifconfig.co/country-iso` avec `%s`).
- **Messages** : éditez les valeurs du tableau `strings`.

## Notes techniques

- Les sessions sont utilisées pour suivre la résolution du CAPTCHA par IP.
- Sans extension GD, le code est affiché en clair dans l'image (fallback texte) afin d'éviter les dépendances.
- Les requêtes CLI retournent immédiatement et ne modifient pas l'état.
- Le fichier `var/state.json` est verrouillé avec `flock` lorsque disponible pour limiter les courses concurrentes.

## Désinstallation

Supprimez la directive `auto_prepend_file` et effacez le répertoire du projet (`var/state.json` peut être supprimé sans risque).
