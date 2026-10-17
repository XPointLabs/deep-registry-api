#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using System.Diagnostics;

namespace Deep.Registry.Api.DirectoryPublication;

// Exact, fixed protocol diagnostics only. Never emit exception text or caller data.
internal static class RouteAuthorityFailure
{
    internal static (string Method, int Offset) Locate(Exception? error, int ownedFrame = 0)
    {
        if (error is null) return ("Unclassified", -1);
        var trace = new StackTrace(error, false);
        for (var index = 0; index < Math.Min(trace.FrameCount, 32); index++)
        {
            var frame = trace.GetFrame(index); var method = frame?.GetMethod(); var type = method?.DeclaringType;
            if (type is null || type.Assembly.GetName().Name is not ("Deep.Registry.Api" or "Deep.Protocol" or "Deep.Protocol.MembershipRoutes")) continue;
            var label = (type.DeclaringType is { } parent ? parent.Name + "+" : "") + type.Name + "." + method!.Name;
            if (label.Length is < 1 or > 240 || !label.All(ch => char.IsAsciiLetterOrDigit(ch) || "_.+<>`".Contains(ch))) continue;
            if (ownedFrame-- > 0) continue;
            return (label, frame!.GetILOffset());
        }
        return ("Unclassified", -1);
    }

    internal static string Classify(Exception? error)
    {
        if (error?.GetType() != typeof(CryptographicException)) return "Unclassified";
        return error.Message switch
        {
            "The XRA1 proposal differs from current DID2 device/delegation scope." =>
                error.Data["Deep.ContactRoute.Scope"] switch
                {
                    "pmt-reference" => "AdvertisementProjection",
                    "device-or-delegation" => "AdvertisementDevice",
                    _ => "AdvertisementScope"
                },
            "The threshold route lifetime exceeds advertisement or issuing authority custody." => "ThresholdLifetime",
            "Selected mailbox replicas do not share a current traffic-key epoch." => "TrafficEpoch",
            "Route witnesses are outside the bounded set." => "WitnessCount",
            "A route witness is absent." => "WitnessAbsent",
            "A route witness is unknown or duplicates an identity/failure domain." => "WitnessIdentity",
            "The route witness threshold is not met." => "WitnessThreshold",
            "A route witness returned an invalid exact signature." => "WitnessSignature",
            "The retained route generation or expiry cannot advance." => "SuccessorAdvance",
            "DID2 route time coverage failed (ThresholdAuthoring; NotBefore)." => "ThresholdNotBefore",
            "DID2 route time coverage failed (ThresholdAuthoring; Expiry)." => "ThresholdExpiry",
            "DID2 route time coverage failed (XRA1; NotBefore)." => "AdvertisementNotBefore",
            "DID2 route time coverage failed (XRA1; Expiry)." => "AdvertisementExpiry",
            "DID2 route time coverage failed (XNH1; Expiry)." => "HeadExpiry",
            "DID2 route time coverage failed (ADH1; Expiry)." => "DirectoryExpiry",
            _ => "Unclassified"
        };
    }
}
#endif
