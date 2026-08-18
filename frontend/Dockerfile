FROM node:22-alpine

WORKDIR /app

ENV NODE_OPTIONS="--dns-result-order=ipv4first"

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]



