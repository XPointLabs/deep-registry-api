ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.301@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.9@sha256:7644f992230d35cf230017189d4038c0ae0f7388b13f4f7ae1900a155bafb597
ARG BUILDPLATFORM

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

FROM ${RUNTIME_IMAGE} AS runtime
ARG DEEP_PROTOCOL_REVISION
LABEL com.xpoint.deep-protocol.revision=${DEEP_PROTOCOL_REVISION}
WORKDIR /app
COPY --from=build /app .
EXPOSE 8080
ENTRYPOINT ["dotnet", "Deep.Registry.Api.dll"]
