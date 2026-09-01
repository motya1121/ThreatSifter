FROM public.ecr.aws/docker/library/python:3.12-slim

# Copy the Lambda Web Adapter binary
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.8.4 /lambda-adapter /opt/extensions/lambda-adapter

WORKDIR /var/task

# Install dependencies
COPY lambda/viewer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY lambda/viewer/app.py .
COPY lambda/viewer/index.html .

# Copy layer/common code
COPY lambda/layer/common /var/task/common

# Setup environment variables for FastAPI and Lambda Web Adapter
ENV PORT=8080
EXPOSE 8080

# Run FastAPI via Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
