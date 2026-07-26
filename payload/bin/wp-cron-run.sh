#!/bin/sh
# WordPress system cron — runs wp-cron.php inside the WordPress container.
podman exec wordpress php /var/www/html/wp-cron.php
