FROM docker.mirror.markant.com/python:3.11

WORKDIR /code/app

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

#COPY ./Client /code/client #is binded into

COPY ./main.py /code/app/main.py

COPY ./gunicorn.config.py /code/app/gunicorn.config.py

#config is determined in gunicorn.config.py 
CMD ["gunicorn", "-c", "gunicorn.config.py", "main:app"]
