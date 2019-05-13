FROM python:3.7-alpine
ARG HTTP_PROXY
ADD . /code
WORKDIR /code
RUN pip3 install -e . --proxy=$HTTP_PROXY 
CMD python3 run.py