FROM python:3.9-slim

# set working dir
WORKDIR /app

# copy application files (assume your app is in ./api relative to the build context)
COPY ./api/ .

# install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# env
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# run the app with the bundled python dev server (ok for local/dev)
CMD ["python", "app.py"]
