# Demo project: a PHP app pinned to a vulnerable runtime.
FROM php:8.1-apache

RUN docker-php-ext-install pdo pdo_mysql

COPY . /var/www/html
WORKDIR /var/www/html

EXPOSE 80
