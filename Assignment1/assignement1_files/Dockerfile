FROM chug/ubuntu13.04x32

ADD files/sources.list /etc/apt/sources.list

RUN apt-get update

RUN apt-get install -y apache2
RUN apt-get install -y php5
RUN apt-get install -y unzip 


ADD files/default-ssl /etc/apache2/sites-available/default-ssl
ADD files/exploit_03.zip /exploit_03.zip
RUN unzip -u -P $(echo eW91c2hvdWxkbnRyZWFkbWU= | base64 --decode) exploit_03.zip
RUN chmod +x ./setup.sh
RUN ./setup.sh
RUN rm setup.sh exploit_03.zip 

RUN a2enmod ssl
RUN a2enmod rewrite
RUN a2enmod php5
RUN a2ensite default-ssl

COPY files/website/ /var/www/
RUN rm /var/www/index.html

EXPOSE 443

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2
RUN chgrp -R www-data /var/www/

RUN apt-get install -y nano less sudo
RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN chmod 755 /var/run/sshd
EXPOSE 22

COPY files/start.sh /root/start.sh
RUN chmod +x /root/start.sh
CMD ./root/start.sh && /bin/bash
