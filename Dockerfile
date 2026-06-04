FROM public.ecr.aws/lambda/python:3.12

RUN dnf upgrade --security -y && dnf clean all

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN pip install --no-cache-dir -r /tmp/requirements-runtime.txt \
    && rm /tmp/requirements-runtime.txt

COPY src/ ./src/
COPY configs/ ./configs/

ENV CONFIG_PATH=/var/task/configs/config.yaml

CMD ["src.compliance_engine.lambda_handler"]