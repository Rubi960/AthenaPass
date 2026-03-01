# SPDX-FileCopyrightText: 2026 Rubi960 & Ryosh1
#
# SPDX-License-Identifier: MIT

FROM python:3-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 4134
CMD ["python", "server.py"]
