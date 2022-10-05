# syntax=docker/dockerfile:1
FROM python:3.8-slim-bullseye

COPY requirements.txt requirements.txt
#RUN apt-get update \
#    && apt-get install -y gcc \
#    && apt-get install -y g++ \
#	&& apt-get install -y libpcap-dev \
#    && apt-get install -y libmagic1

RUN #pip3 install wheel
RUN pip3 install -r requirements.txt

COPY . /src

EXPOSE 18083

CMD cd /src && python3 app.py
#CMD [ "python3", "-m" , "flask", "run", "--host=127.0.0.1"]
