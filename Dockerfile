FROM node:24-alpine

RUN mkdir -p /opt/app
WORKDIR /opt/app

COPY package.json package-lock.json ./
RUN npm install && rm package.json package-lock.json

COPY ./src/ .

USER node:node

EXPOSE 8080/tcp
ENTRYPOINT [ "node", "signalling_server.js" ]
