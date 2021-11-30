FROM leroymerlinbr/php:7.3

USER root

RUN pecl install xdebug \
  && docker-php-ext-enable xdebug

COPY custom.ini /usr/local/etc/php/conf.d/

USER www-data:www-data
