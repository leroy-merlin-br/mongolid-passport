FROM leroymerlinbr/php:7.2

USER root

COPY xdebug.ini /usr/local/etc/php/conf.d/
RUN pecl install xdebug \
  && docker-php-ext-enable xdebug

USER www-data:www-data
