FROM --platform=$BUILDPLATFORM keyval/odiglet-base:v1.5 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg \
    go mod download && go mod verify

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    make build

CMD [ "/app/runtime-detector" ]
