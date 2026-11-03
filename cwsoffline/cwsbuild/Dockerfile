FROM python:3.12-slim

WORKDIR /app

ENV CWS_ARTIFACTS_DIR=/app/artifacts
ENV CWS_ASSETS_DIR=/app/assets
ENV CWS_INTAKE_DIR=/app/intake

COPY cwsoffline/cwsbuild/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cwsoffline/cwsbuild/cwsbuild.py .

CMD ["python", "cwsbuild.py"]
