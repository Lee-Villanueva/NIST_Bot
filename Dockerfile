# ---- build stage ----
FROM golang:1.23-alpine AS build

WORKDIR /src

# install git + certs (common for pulling go modules)
RUN apk add --no-cache git ca-certificates

# leverage docker layer caching
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# build a static-ish binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nist_bot .

# ---- run stage ----
FROM alpine:3.20

WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=build /out/nist_bot ./nist_bot

# don't bake secrets into the image; pass env vars at runtime
CMD ["./nist_bot"]
