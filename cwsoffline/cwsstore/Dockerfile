FROM python:3.12-slim

WORKDIR /store

ENV CWS_ARTIFACTS_DIR=/store/artifacts
ENV CWS_ASSETS_DIR=/store/assets

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8005

ENTRYPOINT ["sh", "/entrypoint.sh"]
