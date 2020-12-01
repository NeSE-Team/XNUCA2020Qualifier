FROM ubuntu

RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
RUN  apt-get clean && apt-get update && apt-get install -y curl \
    && curl -sL https://deb.nodesource.com/setup_10.x | bash -  \
    && apt-get install -y nodejs
COPY src/ /app/
COPY flag /flag
RUN chmod 400 /flag && cp /bin/cat /catforflag && chmod u+s /catforflag && cd /app/ && npm install
USER nobody
ENTRYPOINT ["node", "/app/app.js"]