#Latest Python version supported by Django
FROM python:3.8.6

#Makeing sure that the logs are received in timely manner
ENV PYTHONBUFFERED 1

#Installing system packeges
RUN apt-get update && apt-get upgrade -y

#Setting the working directory
WORKDIR /usr/src/app

# install dependencies
COPY ./src/requirements/production.txt .

RUN pip install --no-cache-dir -r production.txt

# Copy the project files
COPY . .