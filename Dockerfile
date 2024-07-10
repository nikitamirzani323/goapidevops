FROM golang:alpine AS wigomaster
WORKDIR /go/src/bitbucket.org/isbtotogroup/devops_master_api
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o app .


# Moving the binary to the 'final Image' to make it smaller
FROM alpine:latest as wigomasterrelease
WORKDIR /app
RUN apk add tzdata
RUN mkdir -p ./frontend/public
COPY --from=wigomaster /go/src/bitbucket.org/isbtotogroup/devops_master_api/app .
COPY --from=wigomaster /go/src/bitbucket.org/isbtotogroup/devops_master_api/env-sample /app/.env

ENV TZ=Asia/Jakarta
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

EXPOSE 1212
CMD ["./app"]