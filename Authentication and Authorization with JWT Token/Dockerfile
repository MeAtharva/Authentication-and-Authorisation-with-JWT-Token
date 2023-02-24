
FROM node:alpine
WORKDIR /app
COPY package*.json ./
# Install Dependencies
RUN npm ci 
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
