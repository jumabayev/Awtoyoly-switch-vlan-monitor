FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DHCP_SERVER=""
ENV DHCP_USER=""
ENV DHCP_PASS=""
ENV SONICWALL_IP=""
ENV SONICWALL_USER=""
ENV SONICWALL_PASS=""

EXPOSE 5050

CMD ["python", "app.py"]
