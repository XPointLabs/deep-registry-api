ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.301@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.9@sha256:7644f992230d35cf230017189d4038c0ae0f7388b13f4f7ae1900a155bafb597
ARG BUILDPLATFORM
ARG GO_IMAGE=golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c

# The same reviewed observer as DEV, compiled for the image target, not the
# build host. No generated local executable or unpinned provider is copied.
FROM --platform=${BUILDPLATFORM} ${GO_IMAGE} AS nts
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src/nts-observer
COPY --from=deep_devops /tools/nts-observer/go.mod /tools/nts-observer/go.sum ./
RUN go mod download && go mod verify
COPY --from=deep_devops /tools/nts-observer/main.go /tools/nts-observer/main_test.go ./
RUN go test -mod=readonly ./...
RUN set -eux; \
    case "${TARGETARCH}" in amd64|arm64) ;; *) exit 1 ;; esac; \
    GOOS=linux GOARCH="${TARGETARCH}" go build -mod=readonly -trimpath \
      -o /out/deep-nts-observer .

FROM --platform=${BUILDPLATFORM} ${SDK_IMAGE} AS build
ARG TARGETARCH
WORKDIR /src
COPY . ./deep-registry-api
COPY --from=deep_protocol . ./deep-protocol
WORKDIR /src/deep-registry-api
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) dotnet_arch="x64" ;; \
      arm64) dotnet_arch="arm64" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    dotnet restore src/Deep.Registry.Api/Deep.Registry.Api.csproj \
      --runtime "linux-${dotnet_arch}" \
      -p:DeepProtocolLocalCutover=true \
      -p:DeepProtocolSourceCutover=true; \
    dotnet publish src/Deep.Registry.Api/Deep.Registry.Api.csproj \
      --configuration Release \
      --output /app \
      --no-restore \
      -p:DeepProtocolLocalCutover=true \
      -p:DeepProtocolSourceCutover=true \
      --arch "${dotnet_arch}"

# Optional real Linux socket regression lane. No signing keys, state mounts,
# service ports or production mutation; the default image graph is unchanged.
FROM --platform=${BUILDPLATFORM} ${SDK_IMAGE} AS mailbox-signer-tests
WORKDIR /src
COPY . ./deep-registry-api
COPY --from=deep_protocol . ./deep-protocol
WORKDIR /src/deep-registry-api
RUN dotnet test tests/Deep.Registry.Api.Tests/Deep.Registry.Api.Tests.csproj \
    --configuration Release -m:1 -p:UseSharedCompilation=false \
    -p:DeepProtocolLocalCutover=true -p:DeepProtocolSourceCutover=true \
    -p:DirectoryVerifierFocused=true -p:MailboxSignerFocused=true \
    --filter FullyQualifiedName~UnixSocketEd25519ExternalSignerTests \
    --logger trx --results-directory /test-results

FROM ${RUNTIME_IMAGE} AS runtime
ARG DEEP_PROTOCOL_REVISION
ARG DEEP_DEVOPS_REVISION
LABEL com.xpoint.deep-protocol.revision=${DEEP_PROTOCOL_REVISION}
LABEL com.xpoint.deep-devops.revision=${DEEP_DEVOPS_REVISION}
WORKDIR /app
COPY --from=build /app .
COPY --from=nts /out/deep-nts-observer /usr/local/bin/deep-nts-observer
EXPOSE 8080
ENTRYPOINT ["dotnet", "Deep.Registry.Api.dll"]
