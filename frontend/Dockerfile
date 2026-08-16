FROM node:22-alpine

WORKDIR /app

RUN corepack enable

COPY package.json ./
RUN pnpm config set fetch-retry-maxtimeout 120000 && pnpm config set fetch-retries 10 && pnpm install --no-frozen-lockfile


COPY . .

EXPOSE 3000

CMD ["pnpm", "dev"]

