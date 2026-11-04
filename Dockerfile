FROM php:8.4.26-apache

# ---------------------------------------------------------------------------
# php2shell (CVE-2026-109618 / CVE-2026-109619) lab image.
#
# 8.4.26 is the LAST vulnerable 8.4 release. The fix shipped in 8.4.27.
# The tag is pinned on purpose: this image must never be used for anything
# other than an isolated lab.
# ---------------------------------------------------------------------------

# Lab configuration: small memory_limit, large post_max_size, one worker.
COPY php.ini /usr/local/etc/php/conf.d/zz-php2shell-lab.ini
COPY apache/prefork-single.conf /etc/apache2/conf-enabled/zz-php2shell-lab.conf

# Target application. It is deliberately trivial: the exploit runs before it.
COPY app/ /var/www/html/

# The chain's default proof command writes `/out/p1`. Writable by www-data.
RUN mkdir -p /out && chown www-data:www-data /out && chmod 0775 /out

# Surface the exact build in the banner and the logs.
RUN echo "ServerName php2shell-lab" > /etc/apache2/conf-enabled/zz-servername.conf

EXPOSE 80
