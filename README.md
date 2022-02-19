### Backend

- Django REST framework for a powerful API
- Django ORM for interacting with the database

## Development setup 🛠

Steps to locally setup development after cloning the project (tested on Ubuntu).


### Django

Have Python 3.8 installed and in PATH.
Installing Python: https://realpython.com/installing-python/

```sh
python3 --version
# Python 3.8.2
```

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r src/requirements.txt
```
### Database
Run the database creation with `docker-compose`

```sh
docker-compose up -d
```

The Django API is now accessible at `http://localhost:8000/api/sample`    

*Note that it is only tested with Firefox Driver
