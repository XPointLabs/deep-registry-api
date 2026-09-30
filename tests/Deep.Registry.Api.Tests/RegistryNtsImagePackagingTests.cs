namespace Deep.Registry.Api.Tests;

// Source-wiring regression checks only. The Docker build additionally executes
// Go unit tests and builds the actual helper; readiness/device gates are separate.
public sealed class RegistryNtsImagePackagingTests
{
    [Fact]
    public void ObserverUsesLockedSourceAndActualTargetWithoutActivatingTime()
    {
        var docker = Read("Dockerfile");
        Assert.Contains("golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c", docker);
        Assert.Contains("FROM --platform=${BUILDPLATFORM} ${GO_IMAGE} AS nts", docker);
        Assert.Contains("COPY --from=deep_devops /tools/nts-observer/go.mod /tools/nts-observer/go.sum ./", docker);
        Assert.Contains("go mod download && go mod verify", docker);
        Assert.Contains("go test -mod=readonly ./...", docker);
        Assert.Contains("case \"${TARGETARCH}\" in amd64|arm64)", docker);
        Assert.Contains("GOOS=linux GOARCH=\"${TARGETARCH}\" go build -mod=readonly -trimpath", docker);
        Assert.Contains("COPY --from=nts /out/deep-nts-observer /usr/local/bin/deep-nts-observer", docker);
        Assert.Contains("LABEL com.xpoint.deep-devops.revision=${DEEP_DEVOPS_REVISION}", docker);
        Assert.DoesNotContain("GOARCH=arm64 go build", docker);
        Assert.DoesNotContain("AutomaticTrustedTimeEnabled=true", docker);
        Assert.DoesNotContain("provision-state", docker);
    }

    [Theory]
    [InlineData("publish-image.yml")]
    [InlineData("registry-api.yml")]
    public void PublishersBindBothExactCheckedOutSources(string workflow)
    {
        var source = Read(Path.Combine(".github", "workflows", workflow));
        Assert.Contains("repository: ${{ github.repository_owner }}/deep-devops", source);
        Assert.Contains("path: deep-devops", source);
        Assert.Contains("deep_devops=./deep-devops", source);
        Assert.Contains("git -C deep-devops rev-parse HEAD", source);
        Assert.Contains("DEEP_DEVOPS_REVISION=${{ steps.protocol.outputs.devops_sha }}", source);
        Assert.Contains("deep_protocol=./deep-protocol", source);
        Assert.Contains("DEEP_PROTOCOL_REVISION=${{ steps.protocol.outputs.sha }}", source);
    }

    private static string Read(string relative)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
               !File.Exists(Path.Combine(current.FullName, "Deep.Registry.Api.slnx")))
            current = current.Parent;
        var root = current?.FullName ?? throw new InvalidOperationException("Registry repository root absent.");
        return File.ReadAllText(Path.Combine(root, relative)).Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
