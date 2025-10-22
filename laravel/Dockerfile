FROM php:8.2-apache

ARG DEBIAN_FRONTEND=noninteractive


RUN echo "Europe/Zagreb" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata


RUN apt-get update \
    &&  apt-get install -y --no-install-recommends \
        locales apt-utils git libicu-dev curl gnupg2  libgeoip-dev libtool dh-autoreconf g++ libpng-dev libxml2-dev libzip-dev libonig-dev libxslt-dev unzip libpq-dev  nano wget \
        apt-transport-https wget doxygen libcurl4-gnutls-dev tar apache2-dev apache2 flex bison libyajl-dev ssdeep liblua5.2-dev lsb-release ca-certificates 

RUN apt-get install -y libsodium-dev pkg-config
        #software-properties-common
        #libpcre3-dev

RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen  \
    &&  echo "fr_FR.UTF-8 UTF-8" >> /etc/locale.gen \
    &&  locale-gen


RUN wget https://dl-ssl.google.com/dl/linux/direct/mod-pagespeed-stable_current_amd64.deb
RUN dpkg -i mod-pagespeed-*.deb
RUN rm mod-pagespeed-*.deb
RUN sed -i -e 's/ModPagespeed on/ModPagespeed off/g' /etc/apache2/mods-available/pagespeed.conf


RUN a2enmod ssl
RUN a2enmod rewrite 
RUN a2enmod headers
RUN a2enmod proxy_http
RUN a2enmod proxy_http2
RUN a2enmod cache 
RUN a2enmod cache_disk
RUN a2enmod file_cache
RUN a2enmod cache_socache
RUN a2enmod deflate
RUN a2enmod expires
RUN a2enmod info
RUN a2enmod pagespeed



RUN docker-php-ext-install mysqli
RUN docker-php-ext-enable mysqli
RUN docker-php-ext-install opcache
RUN docker-php-ext-install intl
RUN docker-php-ext-install zip
RUN docker-php-ext-install fileinfo
RUN docker-php-ext-install calendar
RUN docker-php-ext-install dom
RUN docker-php-ext-install mbstring
RUN docker-php-ext-install soap

#RUN docker-php-ext-install openssl
RUN docker-php-ext-install sodium
#RUN docker-php-ext-enable mcrypt
    


                    
RUN pecl install apcu && docker-php-ext-enable apcu
RUN pecl install redis && docker-php-ext-enable redis


RUN mkdir /var/cache/apache-web-cache 
RUN chown www-data.www-data /var/cache/apache-web-cache
RUN chmod 755 /var/cache/apache-web-cache 




