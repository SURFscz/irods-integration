# Dockerfile

FROM ubuntu:latest
MAINTAINER Harry Kodden (harry.kodden@surfsara.nl)

RUN apt-get -m update --fix-missing
RUN apt-get -y install apt-utils
RUN apt-get -y install make
RUN apt-get -y install gcc
RUN apt-get -y install git
RUN apt-get -y install libldap2-dev
RUN apt-get -y install libldap-dev
RUN apt-get -y install libsasl2-dev
RUN apt-get -y install locales; update-locale

RUN apt-get -y install python 
RUN apt-get -y install python-dev 
RUN apt-get -y install python-pip; pip install --upgrade pip 

ADD requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt; rm /tmp/requirements.txt

EXPOSE 80

CMD ["bash"]
